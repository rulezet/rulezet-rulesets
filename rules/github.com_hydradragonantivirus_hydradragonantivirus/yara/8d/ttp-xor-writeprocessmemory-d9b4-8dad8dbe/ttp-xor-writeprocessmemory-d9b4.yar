rule TTP_XOR_WriteProcessMemory_d9b4 {
  strings:
    $key_d9b4 = { 8e c6 [2] bc e4 [2] ba d1 [2] 94 d1 [2] ab cd }

  condition:
    any of them
}