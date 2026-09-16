rule TTP_XOR_WriteProcessMemory_c800 {
  strings:
    $key_c800 = { 9f 72 [2] ad 50 [2] ab 65 [2] 85 65 [2] ba 79 }

  condition:
    any of them
}