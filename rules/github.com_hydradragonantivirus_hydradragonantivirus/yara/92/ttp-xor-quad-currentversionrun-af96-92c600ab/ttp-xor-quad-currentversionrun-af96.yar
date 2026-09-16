rule TTP_XOR_QUAD_CurrentVersionRun_af96 {
  strings:
    $key_af96 = { fc f9 [2] d8 f7 [2] f3 db [2] dd f9 [2] c9 e2 [2] c6 f8 [2] d8 e5 [2] da e4 [2] c1 e2 [2] dd e5 [2] c1 ca }

  condition:
    any of them
}