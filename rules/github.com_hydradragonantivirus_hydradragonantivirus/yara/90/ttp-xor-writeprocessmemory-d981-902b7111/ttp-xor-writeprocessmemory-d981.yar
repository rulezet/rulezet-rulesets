rule TTP_XOR_WriteProcessMemory_d981 {
  strings:
    $key_d981 = { 8e f3 [2] bc d1 [2] ba e4 [2] 94 e4 [2] ab f8 }

  condition:
    any of them
}