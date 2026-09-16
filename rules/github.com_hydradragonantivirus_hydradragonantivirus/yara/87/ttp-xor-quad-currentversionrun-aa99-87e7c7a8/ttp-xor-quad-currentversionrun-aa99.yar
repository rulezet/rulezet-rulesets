rule TTP_XOR_QUAD_CurrentVersionRun_aa99 {
  strings:
    $key_aa99 = { f9 f6 [2] dd f8 [2] f6 d4 [2] d8 f6 [2] cc ed [2] c3 f7 [2] dd ea [2] df eb [2] c4 ed [2] d8 ea [2] c4 c5 }

  condition:
    any of them
}