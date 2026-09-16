rule TTP_XOR_QUAD_CurrentVersionRun_b5aa {
  strings:
    $key_b5aa = { e6 c5 [2] c2 cb [2] e9 e7 [2] c7 c5 [2] d3 de [2] dc c4 [2] c2 d9 [2] c0 d8 [2] db de [2] c7 d9 [2] db f6 }

  condition:
    any of them
}