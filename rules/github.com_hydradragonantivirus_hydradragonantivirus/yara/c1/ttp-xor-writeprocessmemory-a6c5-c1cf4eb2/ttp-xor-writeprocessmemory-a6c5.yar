rule TTP_XOR_WriteProcessMemory_a6c5 {
  strings:
    $key_a6c5 = { f1 b7 [2] c3 95 [2] c5 a0 [2] eb a0 [2] d4 bc }

  condition:
    any of them
}