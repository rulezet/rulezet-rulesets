rule TTP_XOR_WriteProcessMemory_5e02 {
  strings:
    $key_5e02 = { 09 70 [2] 3b 52 [2] 3d 67 [2] 13 67 [2] 2c 7b }

  condition:
    any of them
}