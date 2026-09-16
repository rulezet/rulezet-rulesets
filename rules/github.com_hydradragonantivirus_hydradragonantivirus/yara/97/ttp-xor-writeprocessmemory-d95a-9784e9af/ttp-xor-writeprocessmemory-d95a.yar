rule TTP_XOR_WriteProcessMemory_d95a {
  strings:
    $key_d95a = { 8e 28 [2] bc 0a [2] ba 3f [2] 94 3f [2] ab 23 }

  condition:
    any of them
}