rule TTP_XOR_QUAD_CurrentVersionRun_b2a4 {
  strings:
    $key_b2a4 = { e1 cb [2] c5 c5 [2] ee e9 [2] c0 cb [2] d4 d0 [2] db ca [2] c5 d7 [2] c7 d6 [2] dc d0 [2] c0 d7 [2] dc f8 }

  condition:
    any of them
}