rule TTP_XOR_WriteProcessMemory_dfe5 {
  strings:
    $key_dfe5 = { 88 97 [2] ba b5 [2] bc 80 [2] 92 80 [2] ad 9c }

  condition:
    any of them
}