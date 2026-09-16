rule TTP_XOR_WriteProcessMemory_2d6b {
  strings:
    $key_2d6b = { 7a 19 [2] 48 3b [2] 4e 0e [2] 60 0e [2] 5f 12 }

  condition:
    any of them
}