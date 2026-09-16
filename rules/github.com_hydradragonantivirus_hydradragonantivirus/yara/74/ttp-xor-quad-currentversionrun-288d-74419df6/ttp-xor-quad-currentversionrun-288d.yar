rule TTP_XOR_QUAD_CurrentVersionRun_288d {
  strings:
    $key_288d = { 7b e2 [2] 5f ec [2] 74 c0 [2] 5a e2 [2] 4e f9 [2] 41 e3 [2] 5f fe [2] 5d ff [2] 46 f9 [2] 5a fe [2] 46 d1 }

  condition:
    any of them
}