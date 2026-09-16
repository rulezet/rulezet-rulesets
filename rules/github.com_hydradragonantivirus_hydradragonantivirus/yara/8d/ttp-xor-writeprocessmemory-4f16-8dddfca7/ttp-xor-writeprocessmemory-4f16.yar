rule TTP_XOR_WriteProcessMemory_4f16 {
  strings:
    $key_4f16 = { 18 64 [2] 2a 46 [2] 2c 73 [2] 02 73 [2] 3d 6f }

  condition:
    any of them
}