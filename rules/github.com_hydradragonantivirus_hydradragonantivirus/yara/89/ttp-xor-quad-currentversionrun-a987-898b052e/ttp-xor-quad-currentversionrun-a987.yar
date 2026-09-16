rule TTP_XOR_QUAD_CurrentVersionRun_a987 {
  strings:
    $key_a987 = { fa e8 [2] de e6 [2] f5 ca [2] db e8 [2] cf f3 [2] c0 e9 [2] de f4 [2] dc f5 [2] c7 f3 [2] db f4 [2] c7 db }

  condition:
    any of them
}