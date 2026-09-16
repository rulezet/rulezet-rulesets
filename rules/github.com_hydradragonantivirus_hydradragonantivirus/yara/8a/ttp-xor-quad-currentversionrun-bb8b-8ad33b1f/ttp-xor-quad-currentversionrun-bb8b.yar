rule TTP_XOR_QUAD_CurrentVersionRun_bb8b {
  strings:
    $key_bb8b = { e8 e4 [2] cc ea [2] e7 c6 [2] c9 e4 [2] dd ff [2] d2 e5 [2] cc f8 [2] ce f9 [2] d5 ff [2] c9 f8 [2] d5 d7 }

  condition:
    any of them
}