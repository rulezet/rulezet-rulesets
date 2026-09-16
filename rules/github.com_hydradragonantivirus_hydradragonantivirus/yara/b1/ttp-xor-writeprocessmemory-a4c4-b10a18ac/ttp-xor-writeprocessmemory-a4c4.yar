rule TTP_XOR_WriteProcessMemory_a4c4 {
  strings:
    $key_a4c4 = { f3 b6 [2] c1 94 [2] c7 a1 [2] e9 a1 [2] d6 bd }

  condition:
    any of them
}