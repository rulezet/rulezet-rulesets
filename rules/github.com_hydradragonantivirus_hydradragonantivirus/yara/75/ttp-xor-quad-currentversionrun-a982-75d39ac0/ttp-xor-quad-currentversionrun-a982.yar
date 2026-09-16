rule TTP_XOR_QUAD_CurrentVersionRun_a982 {
  strings:
    $key_a982 = { fa ed [2] de e3 [2] f5 cf [2] db ed [2] cf f6 [2] c0 ec [2] de f1 [2] dc f0 [2] c7 f6 [2] db f1 [2] c7 de }

  condition:
    any of them
}