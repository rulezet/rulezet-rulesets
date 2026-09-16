rule TTP_XOR_WriteProcessMemory_cfa1 {
  strings:
    $key_cfa1 = { 98 d3 [2] aa f1 [2] ac c4 [2] 82 c4 [2] bd d8 }

  condition:
    any of them
}