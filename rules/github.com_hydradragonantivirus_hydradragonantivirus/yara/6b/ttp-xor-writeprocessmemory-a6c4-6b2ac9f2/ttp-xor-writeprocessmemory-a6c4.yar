rule TTP_XOR_WriteProcessMemory_a6c4 {
  strings:
    $key_a6c4 = { f1 b6 [2] c3 94 [2] c5 a1 [2] eb a1 [2] d4 bd }

  condition:
    any of them
}