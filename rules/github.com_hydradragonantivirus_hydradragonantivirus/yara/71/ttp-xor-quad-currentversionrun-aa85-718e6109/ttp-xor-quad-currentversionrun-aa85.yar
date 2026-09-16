rule TTP_XOR_QUAD_CurrentVersionRun_aa85 {
  strings:
    $key_aa85 = { f9 ea [2] dd e4 [2] f6 c8 [2] d8 ea [2] cc f1 [2] c3 eb [2] dd f6 [2] df f7 [2] c4 f1 [2] d8 f6 [2] c4 d9 }

  condition:
    any of them
}