rule TTP_XOR_QUAD_CurrentVersionRun_aa8b {
  strings:
    $key_aa8b = { f9 e4 [2] dd ea [2] f6 c6 [2] d8 e4 [2] cc ff [2] c3 e5 [2] dd f8 [2] df f9 [2] c4 ff [2] d8 f8 [2] c4 d7 }

  condition:
    any of them
}