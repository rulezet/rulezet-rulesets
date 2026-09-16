rule TTP_XOR_WriteProcessMemory_c898 {
  strings:
    $key_c898 = { 9f ea [2] ad c8 [2] ab fd [2] 85 fd [2] ba e1 }

  condition:
    any of them
}