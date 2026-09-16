rule TTP_XOR_WriteProcessMemory_d933 {
  strings:
    $key_d933 = { 8e 41 [2] bc 63 [2] ba 56 [2] 94 56 [2] ab 4a }

  condition:
    any of them
}