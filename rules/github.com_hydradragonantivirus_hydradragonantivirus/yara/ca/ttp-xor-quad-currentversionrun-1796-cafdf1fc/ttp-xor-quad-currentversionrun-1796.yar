rule TTP_XOR_QUAD_CurrentVersionRun_1796 {
  strings:
    $key_1796 = { 44 f9 [2] 60 f7 [2] 4b db [2] 65 f9 [2] 71 e2 [2] 7e f8 [2] 60 e5 [2] 62 e4 [2] 79 e2 [2] 65 e5 [2] 79 ca }

  condition:
    any of them
}