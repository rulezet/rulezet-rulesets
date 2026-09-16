rule TTP_XOR_WriteProcessMemory_a4c5 {
  strings:
    $key_a4c5 = { f3 b7 [2] c1 95 [2] c7 a0 [2] e9 a0 [2] d6 bc }

  condition:
    any of them
}