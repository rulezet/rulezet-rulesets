rule TTP_XOR_WriteProcessMemory_f6c5 {
  strings:
    $key_f6c5 = { a1 b7 [2] 93 95 [2] 95 a0 [2] bb a0 [2] 84 bc }

  condition:
    any of them
}