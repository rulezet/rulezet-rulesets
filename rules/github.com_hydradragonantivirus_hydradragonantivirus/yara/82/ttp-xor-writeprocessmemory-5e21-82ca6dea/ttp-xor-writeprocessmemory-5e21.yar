rule TTP_XOR_WriteProcessMemory_5e21 {
  strings:
    $key_5e21 = { 09 53 [2] 3b 71 [2] 3d 44 [2] 13 44 [2] 2c 58 }

  condition:
    any of them
}