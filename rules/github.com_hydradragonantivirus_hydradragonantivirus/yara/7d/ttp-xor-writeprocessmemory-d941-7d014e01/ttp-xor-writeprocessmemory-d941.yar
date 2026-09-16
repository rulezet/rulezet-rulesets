rule TTP_XOR_WriteProcessMemory_d941 {
  strings:
    $key_d941 = { 8e 33 [2] bc 11 [2] ba 24 [2] 94 24 [2] ab 38 }

  condition:
    any of them
}