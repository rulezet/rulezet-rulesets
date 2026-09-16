rule TTP_XOR_WriteProcessMemory_f16b {
  strings:
    $key_f16b = { a6 19 [2] 94 3b [2] 92 0e [2] bc 0e [2] 83 12 }

  condition:
    any of them
}