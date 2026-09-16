rule TTP_XOR_QUAD_CurrentVersionRun_3796 {
  strings:
    $key_3796 = { 64 f9 [2] 40 f7 [2] 6b db [2] 45 f9 [2] 51 e2 [2] 5e f8 [2] 40 e5 [2] 42 e4 [2] 59 e2 [2] 45 e5 [2] 59 ca }

  condition:
    any of them
}