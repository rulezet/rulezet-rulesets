rule TTP_XOR_WriteProcessMemory_d94c {
  strings:
    $key_d94c = { 8e 3e [2] bc 1c [2] ba 29 [2] 94 29 [2] ab 35 }

  condition:
    any of them
}