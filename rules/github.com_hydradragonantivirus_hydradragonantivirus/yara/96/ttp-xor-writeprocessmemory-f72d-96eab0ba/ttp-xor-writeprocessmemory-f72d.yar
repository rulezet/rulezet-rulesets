rule TTP_XOR_WriteProcessMemory_f72d {
  strings:
    $key_f72d = { a0 5f [2] 92 7d [2] 94 48 [2] ba 48 [2] 85 54 }

  condition:
    any of them
}