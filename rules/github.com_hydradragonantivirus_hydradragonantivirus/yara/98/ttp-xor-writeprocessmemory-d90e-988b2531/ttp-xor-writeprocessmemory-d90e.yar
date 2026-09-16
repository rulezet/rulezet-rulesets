rule TTP_XOR_WriteProcessMemory_d90e {
  strings:
    $key_d90e = { 8e 7c [2] bc 5e [2] ba 6b [2] 94 6b [2] ab 77 }

  condition:
    any of them
}