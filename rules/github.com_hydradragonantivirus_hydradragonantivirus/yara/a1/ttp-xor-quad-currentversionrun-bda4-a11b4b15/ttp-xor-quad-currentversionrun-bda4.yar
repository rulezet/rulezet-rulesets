rule TTP_XOR_QUAD_CurrentVersionRun_bda4 {
  strings:
    $key_bda4 = { ee cb [2] ca c5 [2] e1 e9 [2] cf cb [2] db d0 [2] d4 ca [2] ca d7 [2] c8 d6 [2] d3 d0 [2] cf d7 [2] d3 f8 }

  condition:
    any of them
}