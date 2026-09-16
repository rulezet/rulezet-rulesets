rule TTP_XOR_WriteProcessMemory_7c6e {
  strings:
    $key_7c6e = { 2b 1c [2] 19 3e [2] 1f 0b [2] 31 0b [2] 0e 17 }

  condition:
    any of them
}