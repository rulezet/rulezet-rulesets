rule TTP_XOR_WriteProcessMemory_f107 {
  strings:
    $key_f107 = { a6 75 [2] 94 57 [2] 92 62 [2] bc 62 [2] 83 7e }

  condition:
    any of them
}