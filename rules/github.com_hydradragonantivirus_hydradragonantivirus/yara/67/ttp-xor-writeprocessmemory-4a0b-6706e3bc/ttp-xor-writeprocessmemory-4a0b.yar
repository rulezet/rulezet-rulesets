rule TTP_XOR_WriteProcessMemory_4a0b {
  strings:
    $key_4a0b = { 1d 79 [2] 2f 5b [2] 29 6e [2] 07 6e [2] 38 72 }

  condition:
    any of them
}