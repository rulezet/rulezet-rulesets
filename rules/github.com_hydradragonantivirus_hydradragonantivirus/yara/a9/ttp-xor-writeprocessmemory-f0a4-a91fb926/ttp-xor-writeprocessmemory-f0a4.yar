rule TTP_XOR_WriteProcessMemory_f0a4 {
  strings:
    $key_f0a4 = { a7 d6 [2] 95 f4 [2] 93 c1 [2] bd c1 [2] 82 dd }

  condition:
    any of them
}