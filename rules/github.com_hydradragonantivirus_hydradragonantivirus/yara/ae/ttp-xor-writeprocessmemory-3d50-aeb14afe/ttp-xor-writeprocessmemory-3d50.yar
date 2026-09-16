rule TTP_XOR_WriteProcessMemory_3d50 {
  strings:
    $key_3d50 = { 6a 22 [2] 58 00 [2] 5e 35 [2] 70 35 [2] 4f 29 }

  condition:
    any of them
}