rule TTP_XOR_WriteProcessMemory_42c3 {
  strings:
    $key_42c3 = { 15 b1 [2] 27 93 [2] 21 a6 [2] 0f a6 [2] 30 ba }

  condition:
    any of them
}