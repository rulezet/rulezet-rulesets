rule TTP_XOR_QUAD_CurrentVersionRun_a98c {
  strings:
    $key_a98c = { fa e3 [2] de ed [2] f5 c1 [2] db e3 [2] cf f8 [2] c0 e2 [2] de ff [2] dc fe [2] c7 f8 [2] db ff [2] c7 d0 }

  condition:
    any of them
}