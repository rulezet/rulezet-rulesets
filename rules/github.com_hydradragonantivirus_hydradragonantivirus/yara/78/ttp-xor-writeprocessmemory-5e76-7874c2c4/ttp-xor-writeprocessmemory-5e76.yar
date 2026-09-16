rule TTP_XOR_WriteProcessMemory_5e76 {
  strings:
    $key_5e76 = { 09 04 [2] 3b 26 [2] 3d 13 [2] 13 13 [2] 2c 0f }

  condition:
    any of them
}