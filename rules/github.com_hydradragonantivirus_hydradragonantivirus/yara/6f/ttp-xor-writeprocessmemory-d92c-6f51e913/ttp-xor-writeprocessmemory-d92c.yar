rule TTP_XOR_WriteProcessMemory_d92c {
  strings:
    $key_d92c = { 8e 5e [2] bc 7c [2] ba 49 [2] 94 49 [2] ab 55 }

  condition:
    any of them
}