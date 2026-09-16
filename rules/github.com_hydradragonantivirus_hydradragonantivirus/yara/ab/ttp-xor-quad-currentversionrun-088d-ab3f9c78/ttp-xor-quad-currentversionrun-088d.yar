rule TTP_XOR_QUAD_CurrentVersionRun_088d {
  strings:
    $key_088d = { 5b e2 [2] 7f ec [2] 54 c0 [2] 7a e2 [2] 6e f9 [2] 61 e3 [2] 7f fe [2] 7d ff [2] 66 f9 [2] 7a fe [2] 66 d1 }

  condition:
    any of them
}