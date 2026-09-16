rule TTP_XOR_QUAD_CurrentVersionRun_b4b8 {
  strings:
    $key_b4b8 = { e7 d7 [2] c3 d9 [2] e8 f5 [2] c6 d7 [2] d2 cc [2] dd d6 [2] c3 cb [2] c1 ca [2] da cc [2] c6 cb [2] da e4 }

  condition:
    any of them
}