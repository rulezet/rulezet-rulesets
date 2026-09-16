rule TTP_XOR_WriteProcessMemory_d926 {
  strings:
    $key_d926 = { 8e 54 [2] bc 76 [2] ba 43 [2] 94 43 [2] ab 5f }

  condition:
    any of them
}