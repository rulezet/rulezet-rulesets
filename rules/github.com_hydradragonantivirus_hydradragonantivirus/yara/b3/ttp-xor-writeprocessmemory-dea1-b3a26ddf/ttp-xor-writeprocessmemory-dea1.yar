rule TTP_XOR_WriteProcessMemory_dea1 {
  strings:
    $key_dea1 = { 89 d3 [2] bb f1 [2] bd c4 [2] 93 c4 [2] ac d8 }

  condition:
    any of them
}