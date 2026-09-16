rule TTP_XOR_WriteProcessMemory_d90d {
  strings:
    $key_d90d = { 8e 7f [2] bc 5d [2] ba 68 [2] 94 68 [2] ab 74 }

  condition:
    any of them
}