rule TTP_XOR_WriteProcessMemory_5e63 {
  strings:
    $key_5e63 = { 09 11 [2] 3b 33 [2] 3d 06 [2] 13 06 [2] 2c 1a }

  condition:
    any of them
}