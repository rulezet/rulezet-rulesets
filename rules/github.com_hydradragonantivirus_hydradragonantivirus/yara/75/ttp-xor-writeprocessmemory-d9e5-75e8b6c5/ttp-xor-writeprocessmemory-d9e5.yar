rule TTP_XOR_WriteProcessMemory_d9e5 {
  strings:
    $key_d9e5 = { 8e 97 [2] bc b5 [2] ba 80 [2] 94 80 [2] ab 9c }

  condition:
    any of them
}