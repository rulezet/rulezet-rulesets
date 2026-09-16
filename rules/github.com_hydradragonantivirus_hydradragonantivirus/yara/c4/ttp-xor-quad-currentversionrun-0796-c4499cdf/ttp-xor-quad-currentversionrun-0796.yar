rule TTP_XOR_QUAD_CurrentVersionRun_0796 {
  strings:
    $key_0796 = { 54 f9 [2] 70 f7 [2] 5b db [2] 75 f9 [2] 61 e2 [2] 6e f8 [2] 70 e5 [2] 72 e4 [2] 69 e2 [2] 75 e5 [2] 69 ca }

  condition:
    any of them
}