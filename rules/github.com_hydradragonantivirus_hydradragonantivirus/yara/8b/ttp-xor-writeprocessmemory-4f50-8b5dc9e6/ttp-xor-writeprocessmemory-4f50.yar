rule TTP_XOR_WriteProcessMemory_4f50 {
  strings:
    $key_4f50 = { 18 22 [2] 2a 00 [2] 2c 35 [2] 02 35 [2] 3d 29 }

  condition:
    any of them
}