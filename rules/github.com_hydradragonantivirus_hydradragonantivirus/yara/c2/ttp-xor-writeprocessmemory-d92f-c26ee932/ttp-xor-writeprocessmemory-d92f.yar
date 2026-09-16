rule TTP_XOR_WriteProcessMemory_d92f {
  strings:
    $key_d92f = { 8e 5d [2] bc 7f [2] ba 4a [2] 94 4a [2] ab 56 }

  condition:
    any of them
}