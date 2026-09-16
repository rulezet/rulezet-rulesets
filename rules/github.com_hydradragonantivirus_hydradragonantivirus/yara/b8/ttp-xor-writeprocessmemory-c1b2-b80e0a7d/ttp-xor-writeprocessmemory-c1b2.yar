rule TTP_XOR_WriteProcessMemory_c1b2 {
  strings:
    $key_c1b2 = { 96 c0 [2] a4 e2 [2] a2 d7 [2] 8c d7 [2] b3 cb }

  condition:
    any of them
}