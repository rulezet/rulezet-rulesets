rule TTP_XOR_WriteProcessMemory_d92b {
  strings:
    $key_d92b = { 8e 59 [2] bc 7b [2] ba 4e [2] 94 4e [2] ab 52 }

  condition:
    any of them
}