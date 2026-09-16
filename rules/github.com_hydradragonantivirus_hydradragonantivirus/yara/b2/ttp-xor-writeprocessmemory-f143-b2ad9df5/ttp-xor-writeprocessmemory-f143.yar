rule TTP_XOR_WriteProcessMemory_f143 {
  strings:
    $key_f143 = { a6 31 [2] 94 13 [2] 92 26 [2] bc 26 [2] 83 3a }

  condition:
    any of them
}