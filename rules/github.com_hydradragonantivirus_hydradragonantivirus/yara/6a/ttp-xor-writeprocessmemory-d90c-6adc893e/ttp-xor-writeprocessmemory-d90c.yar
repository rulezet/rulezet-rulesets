rule TTP_XOR_WriteProcessMemory_d90c {
  strings:
    $key_d90c = { 8e 7e [2] bc 5c [2] ba 69 [2] 94 69 [2] ab 75 }

  condition:
    any of them
}