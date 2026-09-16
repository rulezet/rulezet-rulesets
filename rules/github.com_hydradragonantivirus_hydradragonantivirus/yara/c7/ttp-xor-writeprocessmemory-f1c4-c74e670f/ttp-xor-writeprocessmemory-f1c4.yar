rule TTP_XOR_WriteProcessMemory_f1c4 {
  strings:
    $key_f1c4 = { a6 b6 [2] 94 94 [2] 92 a1 [2] bc a1 [2] 83 bd }

  condition:
    any of them
}