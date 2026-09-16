rule TTP_XOR_WriteProcessMemory_22c5 {
  strings:
    $key_22c5 = { 75 b7 [2] 47 95 [2] 41 a0 [2] 6f a0 [2] 50 bc }

  condition:
    any of them
}