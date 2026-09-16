rule TTP_XOR_WriteProcessMemory_d9a7 {
  strings:
    $key_d9a7 = { 8e d5 [2] bc f7 [2] ba c2 [2] 94 c2 [2] ab de }

  condition:
    any of them
}