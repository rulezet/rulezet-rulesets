rule TTP_XOR_QUAD_CurrentVersionRun_e88d {
  strings:
    $key_e88d = { bb e2 [2] 9f ec [2] b4 c0 [2] 9a e2 [2] 8e f9 [2] 81 e3 [2] 9f fe [2] 9d ff [2] 86 f9 [2] 9a fe [2] 86 d1 }

  condition:
    any of them
}