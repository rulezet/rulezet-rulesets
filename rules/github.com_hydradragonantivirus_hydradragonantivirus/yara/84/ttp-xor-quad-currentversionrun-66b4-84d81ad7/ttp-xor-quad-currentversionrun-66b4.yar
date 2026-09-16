rule TTP_XOR_QUAD_CurrentVersionRun_66b4 {
  strings:
    $key_66b4 = { 35 db [2] 11 d5 [2] 3a f9 [2] 14 db [2] 00 c0 [2] 0f da [2] 11 c7 [2] 13 c6 [2] 08 c0 [2] 14 c7 [2] 08 e8 }

  condition:
    any of them
}