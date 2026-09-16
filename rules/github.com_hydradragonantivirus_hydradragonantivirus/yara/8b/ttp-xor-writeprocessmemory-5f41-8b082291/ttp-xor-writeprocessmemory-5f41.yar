rule TTP_XOR_WriteProcessMemory_5f41 {
  strings:
    $key_5f41 = { 08 33 [2] 3a 11 [2] 3c 24 [2] 12 24 [2] 2d 38 }

  condition:
    any of them
}