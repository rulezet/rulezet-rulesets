rule TTP_XOR_WriteProcessMemory_d925 {
  strings:
    $key_d925 = { 8e 57 [2] bc 75 [2] ba 40 [2] 94 40 [2] ab 5c }

  condition:
    any of them
}