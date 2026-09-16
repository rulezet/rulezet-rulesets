rule TTP_XOR_QUAD_CurrentVersionRun_af83 {
  strings:
    $key_af83 = { fc ec [2] d8 e2 [2] f3 ce [2] dd ec [2] c9 f7 [2] c6 ed [2] d8 f0 [2] da f1 [2] c1 f7 [2] dd f0 [2] c1 df }

  condition:
    any of them
}