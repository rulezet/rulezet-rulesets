rule TTP_XOR_WriteProcessMemory_d9eb {
  strings:
    $key_d9eb = { 8e 99 [2] bc bb [2] ba 8e [2] 94 8e [2] ab 92 }

  condition:
    any of them
}