rule TTP_XOR_WriteProcessMemory_f18a {
  strings:
    $key_f18a = { a6 f8 [2] 94 da [2] 92 ef [2] bc ef [2] 83 f3 }

  condition:
    any of them
}