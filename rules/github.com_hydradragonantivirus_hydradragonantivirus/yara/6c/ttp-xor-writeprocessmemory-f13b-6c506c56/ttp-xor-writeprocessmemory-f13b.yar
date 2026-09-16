rule TTP_XOR_WriteProcessMemory_f13b {
  strings:
    $key_f13b = { a6 49 [2] 94 6b [2] 92 5e [2] bc 5e [2] 83 42 }

  condition:
    any of them
}