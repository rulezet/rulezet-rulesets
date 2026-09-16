rule TTP_XOR_WriteProcessMemory_f112 {
  strings:
    $key_f112 = { a6 60 [2] 94 42 [2] 92 77 [2] bc 77 [2] 83 6b }

  condition:
    any of them
}