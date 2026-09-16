rule TTP_XOR_QUAD_CurrentVersionRun_b4ab {
  strings:
    $key_b4ab = { e7 c4 [2] c3 ca [2] e8 e6 [2] c6 c4 [2] d2 df [2] dd c5 [2] c3 d8 [2] c1 d9 [2] da df [2] c6 d8 [2] da f7 }

  condition:
    any of them
}