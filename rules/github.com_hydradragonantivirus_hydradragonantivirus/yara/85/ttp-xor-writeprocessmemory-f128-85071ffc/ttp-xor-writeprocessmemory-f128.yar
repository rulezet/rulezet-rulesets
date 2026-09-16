rule TTP_XOR_WriteProcessMemory_f128 {
  strings:
    $key_f128 = { a6 5a [2] 94 78 [2] 92 4d [2] bc 4d [2] 83 51 }

  condition:
    any of them
}