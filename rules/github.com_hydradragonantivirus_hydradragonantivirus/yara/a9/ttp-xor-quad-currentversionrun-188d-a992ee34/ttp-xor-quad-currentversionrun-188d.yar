rule TTP_XOR_QUAD_CurrentVersionRun_188d {
  strings:
    $key_188d = { 4b e2 [2] 6f ec [2] 44 c0 [2] 6a e2 [2] 7e f9 [2] 71 e3 [2] 6f fe [2] 6d ff [2] 76 f9 [2] 6a fe [2] 76 d1 }

  condition:
    any of them
}