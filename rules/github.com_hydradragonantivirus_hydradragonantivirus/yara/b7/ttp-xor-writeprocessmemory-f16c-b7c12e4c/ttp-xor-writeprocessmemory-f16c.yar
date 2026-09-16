rule TTP_XOR_WriteProcessMemory_f16c {
  strings:
    $key_f16c = { a6 1e [2] 94 3c [2] 92 09 [2] bc 09 [2] 83 15 }

  condition:
    any of them
}