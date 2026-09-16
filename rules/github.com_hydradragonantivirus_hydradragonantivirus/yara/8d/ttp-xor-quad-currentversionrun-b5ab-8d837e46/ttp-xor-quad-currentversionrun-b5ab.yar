rule TTP_XOR_QUAD_CurrentVersionRun_b5ab {
  strings:
    $key_b5ab = { e6 c4 [2] c2 ca [2] e9 e6 [2] c7 c4 [2] d3 df [2] dc c5 [2] c2 d8 [2] c0 d9 [2] db df [2] c7 d8 [2] db f7 }

  condition:
    any of them
}