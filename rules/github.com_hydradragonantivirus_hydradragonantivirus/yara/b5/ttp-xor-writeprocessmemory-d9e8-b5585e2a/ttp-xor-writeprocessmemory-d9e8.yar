rule TTP_XOR_WriteProcessMemory_d9e8 {
  strings:
    $key_d9e8 = { 8e 9a [2] bc b8 [2] ba 8d [2] 94 8d [2] ab 91 }

  condition:
    any of them
}