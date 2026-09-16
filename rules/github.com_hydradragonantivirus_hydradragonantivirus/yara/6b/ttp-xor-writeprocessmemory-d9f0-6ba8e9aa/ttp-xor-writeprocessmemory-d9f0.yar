rule TTP_XOR_WriteProcessMemory_d9f0 {
  strings:
    $key_d9f0 = { 8e 82 [2] bc a0 [2] ba 95 [2] 94 95 [2] ab 89 }

  condition:
    any of them
}