rule TTP_XOR_WriteProcessMemory_d967 {
  strings:
    $key_d967 = { 8e 15 [2] bc 37 [2] ba 02 [2] 94 02 [2] ab 1e }

  condition:
    any of them
}