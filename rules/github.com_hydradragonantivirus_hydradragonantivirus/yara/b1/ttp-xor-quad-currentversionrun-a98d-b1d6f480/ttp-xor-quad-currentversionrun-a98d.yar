rule TTP_XOR_QUAD_CurrentVersionRun_a98d {
  strings:
    $key_a98d = { fa e2 [2] de ec [2] f5 c0 [2] db e2 [2] cf f9 [2] c0 e3 [2] de fe [2] dc ff [2] c7 f9 [2] db fe [2] c7 d1 }

  condition:
    any of them
}