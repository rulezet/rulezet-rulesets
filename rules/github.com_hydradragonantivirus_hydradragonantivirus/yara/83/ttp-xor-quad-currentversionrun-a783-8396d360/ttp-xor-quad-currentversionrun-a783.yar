rule TTP_XOR_QUAD_CurrentVersionRun_a783 {
  strings:
    $key_a783 = { f4 ec [2] d0 e2 [2] fb ce [2] d5 ec [2] c1 f7 [2] ce ed [2] d0 f0 [2] d2 f1 [2] c9 f7 [2] d5 f0 [2] c9 df }

  condition:
    any of them
}