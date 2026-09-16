rule TTP_XOR_WriteProcessMemory_57b2 {
  strings:
    $key_57b2 = { 00 c0 [2] 32 e2 [2] 34 d7 [2] 1a d7 [2] 25 cb }

  condition:
    any of them
}