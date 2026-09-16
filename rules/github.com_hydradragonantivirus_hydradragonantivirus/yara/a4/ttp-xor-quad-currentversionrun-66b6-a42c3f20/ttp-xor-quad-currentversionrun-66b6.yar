rule TTP_XOR_QUAD_CurrentVersionRun_66b6 {
  strings:
    $key_66b6 = { 35 d9 [2] 11 d7 [2] 3a fb [2] 14 d9 [2] 00 c2 [2] 0f d8 [2] 11 c5 [2] 13 c4 [2] 08 c2 [2] 14 c5 [2] 08 ea }

  condition:
    any of them
}