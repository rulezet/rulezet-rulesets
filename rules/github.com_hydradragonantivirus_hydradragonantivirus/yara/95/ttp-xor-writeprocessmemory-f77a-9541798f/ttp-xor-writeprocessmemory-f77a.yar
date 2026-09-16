rule TTP_XOR_WriteProcessMemory_f77a {
  strings:
    $key_f77a = { a0 08 [2] 92 2a [2] 94 1f [2] ba 1f [2] 85 03 }

  condition:
    any of them
}