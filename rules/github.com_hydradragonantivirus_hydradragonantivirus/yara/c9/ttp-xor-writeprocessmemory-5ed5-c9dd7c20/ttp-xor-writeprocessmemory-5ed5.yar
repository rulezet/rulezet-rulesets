rule TTP_XOR_WriteProcessMemory_5ed5 {
  strings:
    $key_5ed5 = { 09 a7 [2] 3b 85 [2] 3d b0 [2] 13 b0 [2] 2c ac }

  condition:
    any of them
}