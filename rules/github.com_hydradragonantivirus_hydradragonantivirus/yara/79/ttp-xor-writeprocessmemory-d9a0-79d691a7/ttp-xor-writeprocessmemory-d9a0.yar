rule TTP_XOR_WriteProcessMemory_d9a0 {
  strings:
    $key_d9a0 = { 8e d2 [2] bc f0 [2] ba c5 [2] 94 c5 [2] ab d9 }

  condition:
    any of them
}