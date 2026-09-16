rule TTP_XOR_QUAD_CurrentVersionRun_bb99 {
  strings:
    $key_bb99 = { e8 f6 [2] cc f8 [2] e7 d4 [2] c9 f6 [2] dd ed [2] d2 f7 [2] cc ea [2] ce eb [2] d5 ed [2] c9 ea [2] d5 c5 }

  condition:
    any of them
}