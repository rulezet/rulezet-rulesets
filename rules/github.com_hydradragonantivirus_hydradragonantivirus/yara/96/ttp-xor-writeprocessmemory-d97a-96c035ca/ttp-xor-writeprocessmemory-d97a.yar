rule TTP_XOR_WriteProcessMemory_d97a {
  strings:
    $key_d97a = { 8e 08 [2] bc 2a [2] ba 1f [2] 94 1f [2] ab 03 }

  condition:
    any of them
}