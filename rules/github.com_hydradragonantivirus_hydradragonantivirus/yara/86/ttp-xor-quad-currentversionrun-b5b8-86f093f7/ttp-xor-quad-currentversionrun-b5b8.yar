rule TTP_XOR_QUAD_CurrentVersionRun_b5b8 {
  strings:
    $key_b5b8 = { e6 d7 [2] c2 d9 [2] e9 f5 [2] c7 d7 [2] d3 cc [2] dc d6 [2] c2 cb [2] c0 ca [2] db cc [2] c7 cb [2] db e4 }

  condition:
    any of them
}