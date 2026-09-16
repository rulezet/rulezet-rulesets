rule TTP_XOR_QUAD_CurrentVersionRun_b383 {
  strings:
    $key_b383 = { e0 ec [2] c4 e2 [2] ef ce [2] c1 ec [2] d5 f7 [2] da ed [2] c4 f0 [2] c6 f1 [2] dd f7 [2] c1 f0 [2] dd df }

  condition:
    any of them
}