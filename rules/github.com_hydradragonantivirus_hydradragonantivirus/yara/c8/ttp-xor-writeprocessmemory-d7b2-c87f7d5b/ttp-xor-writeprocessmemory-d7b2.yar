rule TTP_XOR_WriteProcessMemory_d7b2 {
  strings:
    $key_d7b2 = { 80 c0 [2] b2 e2 [2] b4 d7 [2] 9a d7 [2] a5 cb }

  condition:
    any of them
}