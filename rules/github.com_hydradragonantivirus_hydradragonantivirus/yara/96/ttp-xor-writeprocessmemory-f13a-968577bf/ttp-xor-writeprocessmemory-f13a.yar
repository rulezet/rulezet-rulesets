rule TTP_XOR_WriteProcessMemory_f13a {
  strings:
    $key_f13a = { a6 48 [2] 94 6a [2] 92 5f [2] bc 5f [2] 83 43 }

  condition:
    any of them
}