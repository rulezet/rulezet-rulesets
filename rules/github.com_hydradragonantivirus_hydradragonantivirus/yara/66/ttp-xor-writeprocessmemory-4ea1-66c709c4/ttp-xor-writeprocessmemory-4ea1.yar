rule TTP_XOR_WriteProcessMemory_4ea1 {
  strings:
    $key_4ea1 = { 19 d3 [2] 2b f1 [2] 2d c4 [2] 03 c4 [2] 3c d8 }

  condition:
    any of them
}