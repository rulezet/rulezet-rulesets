rule TTP_XOR_WriteProcessMemory_d93f {
  strings:
    $key_d93f = { 8e 4d [2] bc 6f [2] ba 5a [2] 94 5a [2] ab 46 }

  condition:
    any of them
}