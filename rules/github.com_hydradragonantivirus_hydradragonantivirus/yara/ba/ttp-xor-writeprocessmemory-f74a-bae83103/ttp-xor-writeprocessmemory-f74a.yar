rule TTP_XOR_WriteProcessMemory_f74a {
  strings:
    $key_f74a = { a0 38 [2] 92 1a [2] 94 2f [2] ba 2f [2] 85 33 }

  condition:
    any of them
}