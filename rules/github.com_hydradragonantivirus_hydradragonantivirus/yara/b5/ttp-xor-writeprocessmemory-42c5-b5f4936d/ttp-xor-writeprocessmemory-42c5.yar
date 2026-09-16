rule TTP_XOR_WriteProcessMemory_42c5 {
  strings:
    $key_42c5 = { 15 b7 [2] 27 95 [2] 21 a0 [2] 0f a0 [2] 30 bc }

  condition:
    any of them
}