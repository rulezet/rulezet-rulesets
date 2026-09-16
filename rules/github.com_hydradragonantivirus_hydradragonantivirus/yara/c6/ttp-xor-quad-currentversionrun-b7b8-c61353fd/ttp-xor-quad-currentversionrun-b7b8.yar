rule TTP_XOR_QUAD_CurrentVersionRun_b7b8 {
  strings:
    $key_b7b8 = { e4 d7 [2] c0 d9 [2] eb f5 [2] c5 d7 [2] d1 cc [2] de d6 [2] c0 cb [2] c2 ca [2] d9 cc [2] c5 cb [2] d9 e4 }

  condition:
    any of them
}