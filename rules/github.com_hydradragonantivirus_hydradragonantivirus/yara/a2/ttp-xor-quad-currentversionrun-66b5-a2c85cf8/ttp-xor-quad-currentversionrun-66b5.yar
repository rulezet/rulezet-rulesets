rule TTP_XOR_QUAD_CurrentVersionRun_66b5 {
  strings:
    $key_66b5 = { 35 da [2] 11 d4 [2] 3a f8 [2] 14 da [2] 00 c1 [2] 0f db [2] 11 c6 [2] 13 c7 [2] 08 c1 [2] 14 c6 [2] 08 e9 }

  condition:
    any of them
}