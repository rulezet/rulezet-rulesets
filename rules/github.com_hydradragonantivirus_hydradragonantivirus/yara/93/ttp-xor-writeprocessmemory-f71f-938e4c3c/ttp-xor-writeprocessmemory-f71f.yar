rule TTP_XOR_WriteProcessMemory_f71f {
  strings:
    $key_f71f = { a0 6d [2] 92 4f [2] 94 7a [2] ba 7a [2] 85 66 }

  condition:
    any of them
}