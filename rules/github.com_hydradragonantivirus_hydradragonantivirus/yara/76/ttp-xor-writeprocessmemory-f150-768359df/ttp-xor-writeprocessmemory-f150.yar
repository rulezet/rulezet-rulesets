rule TTP_XOR_WriteProcessMemory_f150 {
  strings:
    $key_f150 = { a6 22 [2] 94 00 [2] 92 35 [2] bc 35 [2] 83 29 }

  condition:
    any of them
}