rule TTP_XOR_WriteProcessMemory_d9e1 {
  strings:
    $key_d9e1 = { 8e 93 [2] bc b1 [2] ba 84 [2] 94 84 [2] ab 98 }

  condition:
    any of them
}