rule TTP_XOR_QUAD_CurrentVersionRun_aa84 {
  strings:
    $key_aa84 = { f9 eb [2] dd e5 [2] f6 c9 [2] d8 eb [2] cc f0 [2] c3 ea [2] dd f7 [2] df f6 [2] c4 f0 [2] d8 f7 [2] c4 d8 }

  condition:
    any of them
}