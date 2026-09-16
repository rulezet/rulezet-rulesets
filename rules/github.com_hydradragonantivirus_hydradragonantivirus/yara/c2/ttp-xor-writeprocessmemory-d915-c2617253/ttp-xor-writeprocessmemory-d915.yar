rule TTP_XOR_WriteProcessMemory_d915 {
  strings:
    $key_d915 = { 8e 67 [2] bc 45 [2] ba 70 [2] 94 70 [2] ab 6c }

  condition:
    any of them
}