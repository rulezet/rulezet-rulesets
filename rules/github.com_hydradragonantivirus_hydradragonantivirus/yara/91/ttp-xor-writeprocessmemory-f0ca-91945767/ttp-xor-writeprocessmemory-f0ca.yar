rule TTP_XOR_WriteProcessMemory_f0ca {
  strings:
    $key_f0ca = { a7 b8 [2] 95 9a [2] 93 af [2] bd af [2] 82 b3 }

  condition:
    any of them
}