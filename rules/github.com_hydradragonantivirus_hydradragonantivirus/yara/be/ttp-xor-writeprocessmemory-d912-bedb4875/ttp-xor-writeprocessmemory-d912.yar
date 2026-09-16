rule TTP_XOR_WriteProcessMemory_d912 {
  strings:
    $key_d912 = { 8e 60 [2] bc 42 [2] ba 77 [2] 94 77 [2] ab 6b }

  condition:
    any of them
}