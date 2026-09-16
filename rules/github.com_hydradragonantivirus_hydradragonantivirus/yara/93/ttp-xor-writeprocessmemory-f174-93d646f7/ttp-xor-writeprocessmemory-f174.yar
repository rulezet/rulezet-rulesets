rule TTP_XOR_WriteProcessMemory_f174 {
  strings:
    $key_f174 = { a6 06 [2] 94 24 [2] 92 11 [2] bc 11 [2] 83 0d }

  condition:
    any of them
}