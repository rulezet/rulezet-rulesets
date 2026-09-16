rule TTP_XOR_QUAD_CurrentVersionRun_d397 {
  strings:
    $key_d397 = { 80 f8 [2] a4 f6 [2] 8f da [2] a1 f8 [2] b5 e3 [2] ba f9 [2] a4 e4 [2] a6 e5 [2] bd e3 [2] a1 e4 [2] bd cb }

  condition:
    any of them
}