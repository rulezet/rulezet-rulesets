rule TTP_XOR_WriteProcessMemory_d9a3 {
  strings:
    $key_d9a3 = { 8e d1 [2] bc f3 [2] ba c6 [2] 94 c6 [2] ab da }

  condition:
    any of them
}