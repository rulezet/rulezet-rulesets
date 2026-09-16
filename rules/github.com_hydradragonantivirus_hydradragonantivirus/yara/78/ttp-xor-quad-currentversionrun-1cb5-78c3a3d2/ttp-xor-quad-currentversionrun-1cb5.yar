rule TTP_XOR_QUAD_CurrentVersionRun_1cb5 {
  strings:
    $key_1cb5 = { 4f da [2] 6b d4 [2] 40 f8 [2] 6e da [2] 7a c1 [2] 75 db [2] 6b c6 [2] 69 c7 [2] 72 c1 [2] 6e c6 [2] 72 e9 }

  condition:
    any of them
}