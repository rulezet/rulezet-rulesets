rule TTP_XOR_WriteProcessMemory_f104 {
  strings:
    $key_f104 = { a6 76 [2] 94 54 [2] 92 61 [2] bc 61 [2] 83 7d }

  condition:
    any of them
}