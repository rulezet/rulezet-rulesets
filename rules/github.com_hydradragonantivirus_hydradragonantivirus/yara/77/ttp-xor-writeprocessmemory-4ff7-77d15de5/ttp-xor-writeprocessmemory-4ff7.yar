rule TTP_XOR_WriteProcessMemory_4ff7 {
  strings:
    $key_4ff7 = { 18 85 [2] 2a a7 [2] 2c 92 [2] 02 92 [2] 3d 8e }

  condition:
    any of them
}