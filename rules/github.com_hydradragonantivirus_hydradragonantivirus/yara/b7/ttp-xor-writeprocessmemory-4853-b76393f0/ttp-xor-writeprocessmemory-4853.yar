rule TTP_XOR_WriteProcessMemory_4853 {
  strings:
    $key_4853 = { 1f 21 [2] 2d 03 [2] 2b 36 [2] 05 36 [2] 3a 2a }

  condition:
    any of them
}