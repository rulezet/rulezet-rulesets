rule TTP_XOR_WriteProcessMemory_d9a1 {
  strings:
    $key_d9a1 = { 8e d3 [2] bc f1 [2] ba c4 [2] 94 c4 [2] ab d8 }

  condition:
    any of them
}