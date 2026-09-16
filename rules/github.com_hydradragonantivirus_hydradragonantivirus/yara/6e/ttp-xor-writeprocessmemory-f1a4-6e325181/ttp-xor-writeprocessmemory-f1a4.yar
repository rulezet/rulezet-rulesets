rule TTP_XOR_WriteProcessMemory_f1a4 {
  strings:
    $key_f1a4 = { a6 d6 [2] 94 f4 [2] 92 c1 [2] bc c1 [2] 83 dd }

  condition:
    any of them
}