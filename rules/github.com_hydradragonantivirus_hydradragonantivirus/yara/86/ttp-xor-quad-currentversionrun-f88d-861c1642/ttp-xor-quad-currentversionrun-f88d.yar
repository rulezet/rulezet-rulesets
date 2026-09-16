rule TTP_XOR_QUAD_CurrentVersionRun_f88d {
  strings:
    $key_f88d = { ab e2 [2] 8f ec [2] a4 c0 [2] 8a e2 [2] 9e f9 [2] 91 e3 [2] 8f fe [2] 8d ff [2] 96 f9 [2] 8a fe [2] 96 d1 }

  condition:
    any of them
}