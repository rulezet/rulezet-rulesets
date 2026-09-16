rule TTP_XOR_WriteProcessMemory_d9f1 {
  strings:
    $key_d9f1 = { 8e 83 [2] bc a1 [2] ba 94 [2] 94 94 [2] ab 88 }

  condition:
    any of them
}