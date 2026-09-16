rule TTP_XOR_WriteProcessMemory_a084 {
  strings:
    $key_a084 = { f7 f6 [2] c5 d4 [2] c3 e1 [2] ed e1 [2] d2 fd }

  condition:
    any of them
}