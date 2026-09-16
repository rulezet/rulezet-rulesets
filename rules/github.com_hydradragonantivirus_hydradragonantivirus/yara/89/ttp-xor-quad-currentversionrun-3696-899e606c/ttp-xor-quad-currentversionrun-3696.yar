rule TTP_XOR_QUAD_CurrentVersionRun_3696 {
  strings:
    $key_3696 = { 65 f9 [2] 41 f7 [2] 6a db [2] 44 f9 [2] 50 e2 [2] 5f f8 [2] 41 e5 [2] 43 e4 [2] 58 e2 [2] 44 e5 [2] 58 ca }

  condition:
    any of them
}