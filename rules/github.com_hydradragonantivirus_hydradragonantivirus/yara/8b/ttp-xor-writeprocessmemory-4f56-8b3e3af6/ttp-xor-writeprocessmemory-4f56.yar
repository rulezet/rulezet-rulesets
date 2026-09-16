rule TTP_XOR_WriteProcessMemory_4f56 {
  strings:
    $key_4f56 = { 18 24 [2] 2a 06 [2] 2c 33 [2] 02 33 [2] 3d 2f }

  condition:
    any of them
}