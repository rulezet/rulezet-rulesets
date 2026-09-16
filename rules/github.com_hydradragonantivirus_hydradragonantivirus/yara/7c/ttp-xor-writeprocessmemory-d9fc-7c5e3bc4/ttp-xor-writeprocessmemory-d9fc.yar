rule TTP_XOR_WriteProcessMemory_d9fc {
  strings:
    $key_d9fc = { 8e 8e [2] bc ac [2] ba 99 [2] 94 99 [2] ab 85 }

  condition:
    any of them
}