rule TTP_XOR_WriteProcessMemory_d97d {
  strings:
    $key_d97d = { 8e 0f [2] bc 2d [2] ba 18 [2] 94 18 [2] ab 04 }

  condition:
    any of them
}