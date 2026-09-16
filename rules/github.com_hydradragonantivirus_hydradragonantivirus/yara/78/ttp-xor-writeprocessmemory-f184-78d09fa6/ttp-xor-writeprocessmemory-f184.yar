rule TTP_XOR_WriteProcessMemory_f184 {
  strings:
    $key_f184 = { a6 f6 [2] 94 d4 [2] 92 e1 [2] bc e1 [2] 83 fd }

  condition:
    any of them
}