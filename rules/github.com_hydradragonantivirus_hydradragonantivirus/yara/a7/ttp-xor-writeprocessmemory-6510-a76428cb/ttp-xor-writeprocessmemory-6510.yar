rule TTP_XOR_WriteProcessMemory_6510 {
  strings:
    $key_6510 = { 32 62 [2] 00 40 [2] 06 75 [2] 28 75 [2] 17 69 }

  condition:
    any of them
}