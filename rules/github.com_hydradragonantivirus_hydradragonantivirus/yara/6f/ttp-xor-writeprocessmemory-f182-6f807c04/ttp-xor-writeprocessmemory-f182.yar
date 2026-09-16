rule TTP_XOR_WriteProcessMemory_f182 {
  strings:
    $key_f182 = { a6 f0 [2] 94 d2 [2] 92 e7 [2] bc e7 [2] 83 fb }

  condition:
    any of them
}