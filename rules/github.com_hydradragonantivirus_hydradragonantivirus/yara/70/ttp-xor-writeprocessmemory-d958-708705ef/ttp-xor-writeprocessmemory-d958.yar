rule TTP_XOR_WriteProcessMemory_d958 {
  strings:
    $key_d958 = { 8e 2a [2] bc 08 [2] ba 3d [2] 94 3d [2] ab 21 }

  condition:
    any of them
}