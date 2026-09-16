rule TTP_XOR_WriteProcessMemory_f127 {
  strings:
    $key_f127 = { a6 55 [2] 94 77 [2] 92 42 [2] bc 42 [2] 83 5e }

  condition:
    any of them
}