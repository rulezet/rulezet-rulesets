rule TTP_XOR_WriteProcessMemory_d97c {
  strings:
    $key_d97c = { 8e 0e [2] bc 2c [2] ba 19 [2] 94 19 [2] ab 05 }

  condition:
    any of them
}