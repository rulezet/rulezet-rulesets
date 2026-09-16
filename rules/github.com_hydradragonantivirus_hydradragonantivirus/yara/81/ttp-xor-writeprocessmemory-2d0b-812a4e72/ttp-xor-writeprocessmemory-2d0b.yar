rule TTP_XOR_WriteProcessMemory_2d0b {
  strings:
    $key_2d0b = { 7a 79 [2] 48 5b [2] 4e 6e [2] 60 6e [2] 5f 72 }

  condition:
    any of them
}