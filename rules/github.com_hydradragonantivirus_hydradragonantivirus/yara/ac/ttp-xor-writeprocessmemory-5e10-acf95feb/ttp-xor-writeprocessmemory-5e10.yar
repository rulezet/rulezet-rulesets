rule TTP_XOR_WriteProcessMemory_5e10 {
  strings:
    $key_5e10 = { 09 62 [2] 3b 40 [2] 3d 75 [2] 13 75 [2] 2c 69 }

  condition:
    any of them
}