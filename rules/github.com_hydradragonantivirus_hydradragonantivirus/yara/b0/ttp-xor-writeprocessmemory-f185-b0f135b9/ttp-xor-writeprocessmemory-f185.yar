rule TTP_XOR_WriteProcessMemory_f185 {
  strings:
    $key_f185 = { a6 f7 [2] 94 d5 [2] 92 e0 [2] bc e0 [2] 83 fc }

  condition:
    any of them
}