rule TTP_XOR_QUAD_CurrentVersionRun_2cb5 {
  strings:
    $key_2cb5 = { 7f da [2] 5b d4 [2] 70 f8 [2] 5e da [2] 4a c1 [2] 45 db [2] 5b c6 [2] 59 c7 [2] 42 c1 [2] 5e c6 [2] 42 e9 }

  condition:
    any of them
}