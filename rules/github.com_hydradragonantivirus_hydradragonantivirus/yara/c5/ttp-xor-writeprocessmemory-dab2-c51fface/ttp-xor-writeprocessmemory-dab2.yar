rule TTP_XOR_WriteProcessMemory_dab2 {
  strings:
    $key_dab2 = { 8d c0 [2] bf e2 [2] b9 d7 [2] 97 d7 [2] a8 cb }

  condition:
    any of them
}