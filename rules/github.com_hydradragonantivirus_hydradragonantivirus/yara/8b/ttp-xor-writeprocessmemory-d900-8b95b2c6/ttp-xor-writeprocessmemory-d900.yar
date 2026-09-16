rule TTP_XOR_WriteProcessMemory_d900 {
  strings:
    $key_d900 = { 8e 72 [2] bc 50 [2] ba 65 [2] 94 65 [2] ab 79 }

  condition:
    any of them
}