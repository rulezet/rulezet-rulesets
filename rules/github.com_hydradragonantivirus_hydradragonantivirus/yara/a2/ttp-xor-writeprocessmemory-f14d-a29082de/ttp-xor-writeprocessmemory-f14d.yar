rule TTP_XOR_WriteProcessMemory_f14d {
  strings:
    $key_f14d = { a6 3f [2] 94 1d [2] 92 28 [2] bc 28 [2] 83 34 }

  condition:
    any of them
}