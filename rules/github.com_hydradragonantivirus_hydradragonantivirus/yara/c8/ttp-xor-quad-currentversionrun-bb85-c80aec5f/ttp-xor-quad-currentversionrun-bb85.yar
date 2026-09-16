rule TTP_XOR_QUAD_CurrentVersionRun_bb85 {
  strings:
    $key_bb85 = { e8 ea [2] cc e4 [2] e7 c8 [2] c9 ea [2] dd f1 [2] d2 eb [2] cc f6 [2] ce f7 [2] d5 f1 [2] c9 f6 [2] d5 d9 }

  condition:
    any of them
}