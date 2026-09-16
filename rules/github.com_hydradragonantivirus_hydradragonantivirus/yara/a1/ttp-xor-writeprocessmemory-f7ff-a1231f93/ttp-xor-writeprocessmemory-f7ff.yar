rule TTP_XOR_WriteProcessMemory_f7ff {
  strings:
    $key_f7ff = { a0 8d [2] 92 af [2] 94 9a [2] ba 9a [2] 85 86 }

  condition:
    any of them
}