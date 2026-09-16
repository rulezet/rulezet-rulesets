rule TTP_XOR_WriteProcessMemory_a6b9 {
  strings:
    $key_a6b9 = { f1 cb [2] c3 e9 [2] c5 dc [2] eb dc [2] d4 c0 }

  condition:
    any of them
}