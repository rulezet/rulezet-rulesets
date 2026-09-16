rule TTP_XOR_QUAD_CurrentVersionRun_a899 {
  strings:
    $key_a899 = { fb f6 [2] df f8 [2] f4 d4 [2] da f6 [2] ce ed [2] c1 f7 [2] df ea [2] dd eb [2] c6 ed [2] da ea [2] c6 c5 }

  condition:
    any of them
}