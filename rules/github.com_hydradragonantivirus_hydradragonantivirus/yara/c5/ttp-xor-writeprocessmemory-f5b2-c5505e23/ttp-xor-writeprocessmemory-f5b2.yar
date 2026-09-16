rule TTP_XOR_WriteProcessMemory_f5b2 {
  strings:
    $key_f5b2 = { a2 c0 [2] 90 e2 [2] 96 d7 [2] b8 d7 [2] 87 cb }

  condition:
    any of them
}