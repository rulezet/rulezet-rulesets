rule TTP_XOR_WriteProcessMemory_f77f {
  strings:
    $key_f77f = { a0 0d [2] 92 2f [2] 94 1a [2] ba 1a [2] 85 06 }

  condition:
    any of them
}