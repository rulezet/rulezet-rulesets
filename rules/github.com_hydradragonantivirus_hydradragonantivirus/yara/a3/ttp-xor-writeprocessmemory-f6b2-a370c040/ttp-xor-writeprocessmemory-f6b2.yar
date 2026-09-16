rule TTP_XOR_WriteProcessMemory_f6b2 {
  strings:
    $key_f6b2 = { a1 c0 [2] 93 e2 [2] 95 d7 [2] bb d7 [2] 84 cb }

  condition:
    any of them
}