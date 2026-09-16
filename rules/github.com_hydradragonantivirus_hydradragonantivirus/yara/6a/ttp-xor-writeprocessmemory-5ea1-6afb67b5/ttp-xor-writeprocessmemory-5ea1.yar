rule TTP_XOR_WriteProcessMemory_5ea1 {
  strings:
    $key_5ea1 = { 09 d3 [2] 3b f1 [2] 3d c4 [2] 13 c4 [2] 2c d8 }

  condition:
    any of them
}