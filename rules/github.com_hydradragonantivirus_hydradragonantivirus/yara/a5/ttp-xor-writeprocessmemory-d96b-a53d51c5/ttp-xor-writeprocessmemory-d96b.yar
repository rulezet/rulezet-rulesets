rule TTP_XOR_WriteProcessMemory_d96b {
  strings:
    $key_d96b = { 8e 19 [2] bc 3b [2] ba 0e [2] 94 0e [2] ab 12 }

  condition:
    any of them
}