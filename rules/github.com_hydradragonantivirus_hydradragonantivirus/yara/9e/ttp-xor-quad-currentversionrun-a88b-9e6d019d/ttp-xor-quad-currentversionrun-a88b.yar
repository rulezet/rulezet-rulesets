rule TTP_XOR_QUAD_CurrentVersionRun_a88b {
  strings:
    $key_a88b = { fb e4 [2] df ea [2] f4 c6 [2] da e4 [2] ce ff [2] c1 e5 [2] df f8 [2] dd f9 [2] c6 ff [2] da f8 [2] c6 d7 }

  condition:
    any of them
}