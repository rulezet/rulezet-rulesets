rule TTP_XOR_WriteProcessMemory_51b2 {
  strings:
    $key_51b2 = { 06 c0 [2] 34 e2 [2] 32 d7 [2] 1c d7 [2] 23 cb }

  condition:
    any of them
}