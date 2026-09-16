rule TTP_XOR_WriteProcessMemory_d95f {
  strings:
    $key_d95f = { 8e 2d [2] bc 0f [2] ba 3a [2] 94 3a [2] ab 26 }

  condition:
    any of them
}