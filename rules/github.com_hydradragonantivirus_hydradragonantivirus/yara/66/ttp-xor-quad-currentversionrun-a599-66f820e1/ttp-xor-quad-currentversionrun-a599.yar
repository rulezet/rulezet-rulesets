rule TTP_XOR_QUAD_CurrentVersionRun_a599 {
  strings:
    $key_a599 = { f6 f6 [2] d2 f8 [2] f9 d4 [2] d7 f6 [2] c3 ed [2] cc f7 [2] d2 ea [2] d0 eb [2] cb ed [2] d7 ea [2] cb c5 }

  condition:
    any of them
}