rule TTP_XOR_WriteProcessMemory_f16f {
  strings:
    $key_f16f = { a6 1d [2] 94 3f [2] 92 0a [2] bc 0a [2] 83 16 }

  condition:
    any of them
}