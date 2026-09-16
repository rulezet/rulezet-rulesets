rule TTP_XOR_WriteProcessMemory_c4b2 {
  strings:
    $key_c4b2 = { 93 c0 [2] a1 e2 [2] a7 d7 [2] 89 d7 [2] b6 cb }

  condition:
    any of them
}