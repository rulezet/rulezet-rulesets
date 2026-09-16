rule TTP_XOR_WriteProcessMemory_d97f {
  strings:
    $key_d97f = { 8e 0d [2] bc 2f [2] ba 1a [2] 94 1a [2] ab 06 }

  condition:
    any of them
}