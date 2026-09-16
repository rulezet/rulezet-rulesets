rule TTP_XOR_WriteProcessMemory_5e06 {
  strings:
    $key_5e06 = { 09 74 [2] 3b 56 [2] 3d 63 [2] 13 63 [2] 2c 7f }

  condition:
    any of them
}