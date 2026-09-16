rule TTP_XOR_WriteProcessMemory_d95d {
  strings:
    $key_d95d = { 8e 2f [2] bc 0d [2] ba 38 [2] 94 38 [2] ab 24 }

  condition:
    any of them
}