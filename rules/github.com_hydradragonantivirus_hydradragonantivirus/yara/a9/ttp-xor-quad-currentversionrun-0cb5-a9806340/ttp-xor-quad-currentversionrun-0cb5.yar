rule TTP_XOR_QUAD_CurrentVersionRun_0cb5 {
  strings:
    $key_0cb5 = { 5f da [2] 7b d4 [2] 50 f8 [2] 7e da [2] 6a c1 [2] 65 db [2] 7b c6 [2] 79 c7 [2] 62 c1 [2] 7e c6 [2] 62 e9 }

  condition:
    any of them
}