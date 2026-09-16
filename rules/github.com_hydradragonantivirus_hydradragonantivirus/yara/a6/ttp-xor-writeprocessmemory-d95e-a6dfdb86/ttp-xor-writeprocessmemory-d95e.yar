rule TTP_XOR_WriteProcessMemory_d95e {
  strings:
    $key_d95e = { 8e 2c [2] bc 0e [2] ba 3b [2] 94 3b [2] ab 27 }

  condition:
    any of them
}