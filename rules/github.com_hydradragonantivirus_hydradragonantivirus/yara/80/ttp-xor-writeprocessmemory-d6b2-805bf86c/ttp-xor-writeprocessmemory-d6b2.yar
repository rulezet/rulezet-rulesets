rule TTP_XOR_WriteProcessMemory_d6b2 {
  strings:
    $key_d6b2 = { 81 c0 [2] b3 e2 [2] b5 d7 [2] 9b d7 [2] a4 cb }

  condition:
    any of them
}