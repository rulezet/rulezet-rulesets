rule TTP_XOR_WriteProcessMemory_f74d {
  strings:
    $key_f74d = { a0 3f [2] 92 1d [2] 94 28 [2] ba 28 [2] 85 34 }

  condition:
    any of them
}