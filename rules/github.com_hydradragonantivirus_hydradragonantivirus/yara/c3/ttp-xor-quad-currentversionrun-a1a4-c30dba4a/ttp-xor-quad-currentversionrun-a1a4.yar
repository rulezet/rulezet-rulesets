rule TTP_XOR_QUAD_CurrentVersionRun_a1a4 {
  strings:
    $key_a1a4 = { f2 cb [2] d6 c5 [2] fd e9 [2] d3 cb [2] c7 d0 [2] c8 ca [2] d6 d7 [2] d4 d6 [2] cf d0 [2] d3 d7 [2] cf f8 }

  condition:
    any of them
}