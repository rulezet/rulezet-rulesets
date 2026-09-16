rule TTP_XOR_QUAD_CurrentVersionRun_a4ab {
  strings:
    $key_a4ab = { f7 c4 [2] d3 ca [2] f8 e6 [2] d6 c4 [2] c2 df [2] cd c5 [2] d3 d8 [2] d1 d9 [2] ca df [2] d6 d8 [2] ca f7 }

  condition:
    any of them
}