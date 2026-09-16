rule TTP_XOR_QUAD_CurrentVersionRun_3cb5 {
  strings:
    $key_3cb5 = { 6f da [2] 4b d4 [2] 60 f8 [2] 4e da [2] 5a c1 [2] 55 db [2] 4b c6 [2] 49 c7 [2] 52 c1 [2] 4e c6 [2] 52 e9 }

  condition:
    any of them
}