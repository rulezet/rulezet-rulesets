rule TTP_XOR_WriteProcessMemory_f1a8 {
  strings:
    $key_f1a8 = { a6 da [2] 94 f8 [2] 92 cd [2] bc cd [2] 83 d1 }

  condition:
    any of them
}