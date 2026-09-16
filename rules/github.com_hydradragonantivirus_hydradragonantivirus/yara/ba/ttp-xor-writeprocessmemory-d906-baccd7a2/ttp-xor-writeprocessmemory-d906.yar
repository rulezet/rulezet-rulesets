rule TTP_XOR_WriteProcessMemory_d906 {
  strings:
    $key_d906 = { 8e 74 [2] bc 56 [2] ba 63 [2] 94 63 [2] ab 7f }

  condition:
    any of them
}