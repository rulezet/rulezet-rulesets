rule TTP_XOR_WriteProcessMemory_71b2 {
  strings:
    $key_71b2 = { 26 c0 [2] 14 e2 [2] 12 d7 [2] 3c d7 [2] 03 cb }

  condition:
    any of them
}