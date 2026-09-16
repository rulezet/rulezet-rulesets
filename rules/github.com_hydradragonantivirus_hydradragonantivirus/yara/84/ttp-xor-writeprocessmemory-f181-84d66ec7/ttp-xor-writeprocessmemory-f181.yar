rule TTP_XOR_WriteProcessMemory_f181 {
  strings:
    $key_f181 = { a6 f3 [2] 94 d1 [2] 92 e4 [2] bc e4 [2] 83 f8 }

  condition:
    any of them
}