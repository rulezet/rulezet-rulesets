rule TTP_XOR_WriteProcessMemory_c2b2 {
  strings:
    $key_c2b2 = { 95 c0 [2] a7 e2 [2] a1 d7 [2] 8f d7 [2] b0 cb }

  condition:
    any of them
}