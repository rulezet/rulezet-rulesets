rule TTP_XOR_WriteProcessMemory_42c0 {
  strings:
    $key_42c0 = { 15 b2 [2] 27 90 [2] 21 a5 [2] 0f a5 [2] 30 b9 }

  condition:
    any of them
}