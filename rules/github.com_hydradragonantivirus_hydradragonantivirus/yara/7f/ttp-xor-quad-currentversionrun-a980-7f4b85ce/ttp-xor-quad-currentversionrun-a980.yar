rule TTP_XOR_QUAD_CurrentVersionRun_a980 {
  strings:
    $key_a980 = { fa ef [2] de e1 [2] f5 cd [2] db ef [2] cf f4 [2] c0 ee [2] de f3 [2] dc f2 [2] c7 f4 [2] db f3 [2] c7 dc }

  condition:
    any of them
}