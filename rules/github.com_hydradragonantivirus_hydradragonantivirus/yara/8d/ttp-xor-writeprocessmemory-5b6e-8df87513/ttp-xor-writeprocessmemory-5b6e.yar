rule TTP_XOR_WriteProcessMemory_5b6e {
  strings:
    $key_5b6e = { 0c 1c [2] 3e 3e [2] 38 0b [2] 16 0b [2] 29 17 }

  condition:
    any of them
}