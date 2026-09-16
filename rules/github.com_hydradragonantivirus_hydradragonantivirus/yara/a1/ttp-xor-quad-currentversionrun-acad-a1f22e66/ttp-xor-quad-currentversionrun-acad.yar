rule TTP_XOR_QUAD_CurrentVersionRun_acad {
  strings:
    $key_acad = { ff c2 [2] db cc [2] f0 e0 [2] de c2 [2] ca d9 [2] c5 c3 [2] db de [2] d9 df [2] c2 d9 [2] de de [2] c2 f1 }

  condition:
    any of them
}