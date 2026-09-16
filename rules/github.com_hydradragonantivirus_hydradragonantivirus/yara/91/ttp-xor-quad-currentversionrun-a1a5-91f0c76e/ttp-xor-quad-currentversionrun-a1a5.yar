rule TTP_XOR_QUAD_CurrentVersionRun_a1a5 {
  strings:
    $key_a1a5 = { f2 ca [2] d6 c4 [2] fd e8 [2] d3 ca [2] c7 d1 [2] c8 cb [2] d6 d6 [2] d4 d7 [2] cf d1 [2] d3 d6 [2] cf f9 }

  condition:
    any of them
}