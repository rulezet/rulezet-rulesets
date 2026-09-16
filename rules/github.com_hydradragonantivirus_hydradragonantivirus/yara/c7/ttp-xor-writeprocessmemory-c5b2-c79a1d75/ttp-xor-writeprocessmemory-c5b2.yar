rule TTP_XOR_WriteProcessMemory_c5b2 {
  strings:
    $key_c5b2 = { 92 c0 [2] a0 e2 [2] a6 d7 [2] 88 d7 [2] b7 cb }

  condition:
    any of them
}