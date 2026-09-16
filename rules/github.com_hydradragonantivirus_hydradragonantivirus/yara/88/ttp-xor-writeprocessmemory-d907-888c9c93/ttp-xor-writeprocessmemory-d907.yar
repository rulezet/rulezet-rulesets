rule TTP_XOR_WriteProcessMemory_d907 {
  strings:
    $key_d907 = { 8e 75 [2] bc 57 [2] ba 62 [2] 94 62 [2] ab 7e }

  condition:
    any of them
}