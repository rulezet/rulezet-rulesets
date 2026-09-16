rule TTP_XOR_WriteProcessMemory_7ea1 {
  strings:
    $key_7ea1 = { 29 d3 [2] 1b f1 [2] 1d c4 [2] 33 c4 [2] 0c d8 }

  condition:
    any of them
}