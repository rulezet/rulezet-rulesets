rule TTP_XOR_WriteProcessMemory_d9d2 {
  strings:
    $key_d9d2 = { 8e a0 [2] bc 82 [2] ba b7 [2] 94 b7 [2] ab ab }

  condition:
    any of them
}