rule TTP_XOR_WriteProcessMemory_0e6e {
  strings:
    $key_0e6e = { 59 1c [2] 6b 3e [2] 6d 0b [2] 43 0b [2] 7c 17 }

  condition:
    any of them
}