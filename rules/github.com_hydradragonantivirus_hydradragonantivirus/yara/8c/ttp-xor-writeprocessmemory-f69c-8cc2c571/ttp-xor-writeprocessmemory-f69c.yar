rule TTP_XOR_WriteProcessMemory_f69c {
  strings:
    $key_f69c = { a1 ee [2] 93 cc [2] 95 f9 [2] bb f9 [2] 84 e5 }

  condition:
    any of them
}