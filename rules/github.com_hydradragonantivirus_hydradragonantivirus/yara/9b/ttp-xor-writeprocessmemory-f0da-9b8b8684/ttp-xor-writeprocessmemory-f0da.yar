rule TTP_XOR_WriteProcessMemory_f0da {
  strings:
    $key_f0da = { a7 a8 [2] 95 8a [2] 93 bf [2] bd bf [2] 82 a3 }

  condition:
    any of them
}