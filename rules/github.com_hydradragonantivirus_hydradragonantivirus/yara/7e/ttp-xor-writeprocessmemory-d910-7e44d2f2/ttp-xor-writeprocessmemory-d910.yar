rule TTP_XOR_WriteProcessMemory_d910 {
  strings:
    $key_d910 = { 8e 62 [2] bc 40 [2] ba 75 [2] 94 75 [2] ab 69 }

  condition:
    any of them
}