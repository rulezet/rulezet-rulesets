rule TTP_XOR_QUAD_CurrentVersionRun_af99 {
  strings:
    $key_af99 = { fc f6 [2] d8 f8 [2] f3 d4 [2] dd f6 [2] c9 ed [2] c6 f7 [2] d8 ea [2] da eb [2] c1 ed [2] dd ea [2] c1 c5 }

  condition:
    any of them
}