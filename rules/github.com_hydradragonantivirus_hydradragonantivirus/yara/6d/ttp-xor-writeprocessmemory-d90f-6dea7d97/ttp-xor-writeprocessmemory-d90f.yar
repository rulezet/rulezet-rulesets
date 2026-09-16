rule TTP_XOR_WriteProcessMemory_d90f {
  strings:
    $key_d90f = { 8e 7d [2] bc 5f [2] ba 6a [2] 94 6a [2] ab 76 }

  condition:
    any of them
}