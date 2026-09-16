rule TTP_XOR_WriteProcessMemory_f171 {
  strings:
    $key_f171 = { a6 03 [2] 94 21 [2] 92 14 [2] bc 14 [2] 83 08 }

  condition:
    any of them
}