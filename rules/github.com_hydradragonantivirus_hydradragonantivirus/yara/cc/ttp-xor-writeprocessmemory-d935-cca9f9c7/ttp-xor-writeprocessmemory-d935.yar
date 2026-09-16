rule TTP_XOR_WriteProcessMemory_d935 {
  strings:
    $key_d935 = { 8e 47 [2] bc 65 [2] ba 50 [2] 94 50 [2] ab 4c }

  condition:
    any of them
}