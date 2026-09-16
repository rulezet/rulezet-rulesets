rule TTP_XOR_WriteProcessMemory_d950 {
  strings:
    $key_d950 = { 8e 22 [2] bc 00 [2] ba 35 [2] 94 35 [2] ab 29 }

  condition:
    any of them
}