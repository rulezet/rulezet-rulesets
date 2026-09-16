rule TTP_XOR_WriteProcessMemory_f1c3 {
  strings:
    $key_f1c3 = { a6 b1 [2] 94 93 [2] 92 a6 [2] bc a6 [2] 83 ba }

  condition:
    any of them
}