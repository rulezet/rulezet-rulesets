rule TTP_XOR_WriteProcessMemory_f1c0 {
  strings:
    $key_f1c0 = { a6 b2 [2] 94 90 [2] 92 a5 [2] bc a5 [2] 83 b9 }

  condition:
    any of them
}