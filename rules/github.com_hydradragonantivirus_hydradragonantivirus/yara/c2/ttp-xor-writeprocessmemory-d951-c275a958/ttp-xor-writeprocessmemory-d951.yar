rule TTP_XOR_WriteProcessMemory_d951 {
  strings:
    $key_d951 = { 8e 23 [2] bc 01 [2] ba 34 [2] 94 34 [2] ab 28 }

  condition:
    any of them
}