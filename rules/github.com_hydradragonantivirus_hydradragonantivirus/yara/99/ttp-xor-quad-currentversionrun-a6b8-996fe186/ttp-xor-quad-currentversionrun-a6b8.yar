rule TTP_XOR_QUAD_CurrentVersionRun_a6b8 {
  strings:
    $key_a6b8 = { f5 d7 [2] d1 d9 [2] fa f5 [2] d4 d7 [2] c0 cc [2] cf d6 [2] d1 cb [2] d3 ca [2] c8 cc [2] d4 cb [2] c8 e4 }

  condition:
    any of them
}