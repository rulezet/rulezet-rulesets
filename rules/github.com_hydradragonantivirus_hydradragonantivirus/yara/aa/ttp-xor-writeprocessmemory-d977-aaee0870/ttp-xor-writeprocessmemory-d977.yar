rule TTP_XOR_WriteProcessMemory_d977 {
  strings:
    $key_d977 = { 8e 05 [2] bc 27 [2] ba 12 [2] 94 12 [2] ab 0e }

  condition:
    any of them
}