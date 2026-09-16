rule TTP_XOR_WriteProcessMemory_5ec5 {
  strings:
    $key_5ec5 = { 09 b7 [2] 3b 95 [2] 3d a0 [2] 13 a0 [2] 2c bc }

  condition:
    any of them
}