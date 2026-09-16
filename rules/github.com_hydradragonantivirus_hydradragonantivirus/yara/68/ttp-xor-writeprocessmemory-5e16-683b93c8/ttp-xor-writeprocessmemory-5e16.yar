rule TTP_XOR_WriteProcessMemory_5e16 {
  strings:
    $key_5e16 = { 09 64 [2] 3b 46 [2] 3d 73 [2] 13 73 [2] 2c 6f }

  condition:
    any of them
}