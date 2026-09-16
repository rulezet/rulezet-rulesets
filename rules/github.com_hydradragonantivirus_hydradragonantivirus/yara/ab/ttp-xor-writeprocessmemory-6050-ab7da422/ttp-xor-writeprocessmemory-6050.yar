rule TTP_XOR_WriteProcessMemory_6050 {
  strings:
    $key_6050 = { 37 22 [2] 05 00 [2] 03 35 [2] 2d 35 [2] 12 29 }

  condition:
    any of them
}