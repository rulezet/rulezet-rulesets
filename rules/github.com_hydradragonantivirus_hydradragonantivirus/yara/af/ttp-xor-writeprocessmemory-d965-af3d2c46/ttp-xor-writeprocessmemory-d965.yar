rule TTP_XOR_WriteProcessMemory_d965 {
  strings:
    $key_d965 = { 8e 17 [2] bc 35 [2] ba 00 [2] 94 00 [2] ab 1c }

  condition:
    any of them
}