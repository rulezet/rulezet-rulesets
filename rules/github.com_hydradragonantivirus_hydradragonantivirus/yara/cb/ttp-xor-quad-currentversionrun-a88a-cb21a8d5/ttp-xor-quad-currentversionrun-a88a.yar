rule TTP_XOR_QUAD_CurrentVersionRun_a88a {
  strings:
    $key_a88a = { fb e5 [2] df eb [2] f4 c7 [2] da e5 [2] ce fe [2] c1 e4 [2] df f9 [2] dd f8 [2] c6 fe [2] da f9 [2] c6 d6 }

  condition:
    any of them
}