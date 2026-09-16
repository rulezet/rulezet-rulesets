rule TTP_XOR_WriteProcessMemory_5ef7 {
  strings:
    $key_5ef7 = { 09 85 [2] 3b a7 [2] 3d 92 [2] 13 92 [2] 2c 8e }

  condition:
    any of them
}