rule TTP_XOR_WriteProcessMemory_f1d4 {
  strings:
    $key_f1d4 = { a6 a6 [2] 94 84 [2] 92 b1 [2] bc b1 [2] 83 ad }

  condition:
    any of them
}