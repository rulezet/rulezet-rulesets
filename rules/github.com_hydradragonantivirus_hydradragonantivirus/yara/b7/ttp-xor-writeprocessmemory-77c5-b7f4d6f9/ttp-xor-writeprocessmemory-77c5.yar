rule TTP_XOR_WriteProcessMemory_77c5 {
  strings:
    $key_77c5 = { 20 b7 [2] 12 95 [2] 14 a0 [2] 3a a0 [2] 05 bc }

  condition:
    any of them
}