rule TTP_XOR_QUAD_CurrentVersionRun_af97 {
  strings:
    $key_af97 = { fc f8 [2] d8 f6 [2] f3 da [2] dd f8 [2] c9 e3 [2] c6 f9 [2] d8 e4 [2] da e5 [2] c1 e3 [2] dd e4 [2] c1 cb }

  condition:
    any of them
}