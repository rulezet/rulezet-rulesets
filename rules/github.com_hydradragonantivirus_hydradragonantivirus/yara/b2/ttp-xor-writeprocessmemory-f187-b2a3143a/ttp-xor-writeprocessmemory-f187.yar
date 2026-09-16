rule TTP_XOR_WriteProcessMemory_f187 {
  strings:
    $key_f187 = { a6 f5 [2] 94 d7 [2] 92 e2 [2] bc e2 [2] 83 fe }

  condition:
    any of them
}