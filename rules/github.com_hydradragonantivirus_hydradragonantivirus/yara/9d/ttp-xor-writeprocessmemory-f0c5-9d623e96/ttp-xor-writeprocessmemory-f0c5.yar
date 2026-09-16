rule TTP_XOR_WriteProcessMemory_f0c5 {
  strings:
    $key_f0c5 = { a7 b7 [2] 95 95 [2] 93 a0 [2] bd a0 [2] 82 bc }

  condition:
    any of them
}