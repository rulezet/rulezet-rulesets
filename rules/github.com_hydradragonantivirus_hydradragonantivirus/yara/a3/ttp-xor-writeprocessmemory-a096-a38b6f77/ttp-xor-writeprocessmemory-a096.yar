rule TTP_XOR_WriteProcessMemory_a096 {
  strings:
    $key_a096 = { f7 e4 [2] c5 c6 [2] c3 f3 [2] ed f3 [2] d2 ef }

  condition:
    any of them
}