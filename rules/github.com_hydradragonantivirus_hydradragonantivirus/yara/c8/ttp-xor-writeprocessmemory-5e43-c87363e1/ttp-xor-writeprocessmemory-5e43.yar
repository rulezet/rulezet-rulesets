rule TTP_XOR_WriteProcessMemory_5e43 {
  strings:
    $key_5e43 = { 09 31 [2] 3b 13 [2] 3d 26 [2] 13 26 [2] 2c 3a }

  condition:
    any of them
}