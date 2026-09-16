rule TTP_XOR_WriteProcessMemory_d9e2 {
  strings:
    $key_d9e2 = { 8e 90 [2] bc b2 [2] ba 87 [2] 94 87 [2] ab 9b }

  condition:
    any of them
}