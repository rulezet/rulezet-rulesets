rule TTP_XOR_WriteProcessMemory_a596 {
  strings:
    $key_a596 = { f2 e4 [2] c0 c6 [2] c6 f3 [2] e8 f3 [2] d7 ef }

  condition:
    any of them
}