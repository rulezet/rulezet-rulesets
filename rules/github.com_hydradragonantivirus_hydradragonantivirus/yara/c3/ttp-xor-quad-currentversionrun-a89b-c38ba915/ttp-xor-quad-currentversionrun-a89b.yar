rule TTP_XOR_QUAD_CurrentVersionRun_a89b {
  strings:
    $key_a89b = { fb f4 [2] df fa [2] f4 d6 [2] da f4 [2] ce ef [2] c1 f5 [2] df e8 [2] dd e9 [2] c6 ef [2] da e8 [2] c6 c7 }

  condition:
    any of them
}