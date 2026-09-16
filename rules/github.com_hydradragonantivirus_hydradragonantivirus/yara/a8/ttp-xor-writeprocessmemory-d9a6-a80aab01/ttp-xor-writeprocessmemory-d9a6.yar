rule TTP_XOR_WriteProcessMemory_d9a6 {
  strings:
    $key_d9a6 = { 8e d4 [2] bc f6 [2] ba c3 [2] 94 c3 [2] ab df }

  condition:
    any of them
}