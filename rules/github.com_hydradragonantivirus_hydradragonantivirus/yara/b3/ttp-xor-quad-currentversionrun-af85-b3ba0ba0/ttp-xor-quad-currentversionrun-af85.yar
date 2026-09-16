rule TTP_XOR_QUAD_CurrentVersionRun_af85 {
  strings:
    $key_af85 = { fc ea [2] d8 e4 [2] f3 c8 [2] dd ea [2] c9 f1 [2] c6 eb [2] d8 f6 [2] da f7 [2] c1 f1 [2] dd f6 [2] c1 d9 }

  condition:
    any of them
}