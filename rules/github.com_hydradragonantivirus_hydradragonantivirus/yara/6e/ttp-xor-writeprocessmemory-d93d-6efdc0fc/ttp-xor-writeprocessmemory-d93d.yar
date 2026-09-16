rule TTP_XOR_WriteProcessMemory_d93d {
  strings:
    $key_d93d = { 8e 4f [2] bc 6d [2] ba 58 [2] 94 58 [2] ab 44 }

  condition:
    any of them
}