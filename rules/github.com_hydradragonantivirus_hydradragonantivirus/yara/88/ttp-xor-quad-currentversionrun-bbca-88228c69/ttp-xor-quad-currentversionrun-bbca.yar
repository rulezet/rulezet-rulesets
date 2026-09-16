rule TTP_XOR_QUAD_CurrentVersionRun_bbca {
  strings:
    $key_bbca = { e8 a5 [2] cc ab [2] e7 87 [2] c9 a5 [2] dd be [2] d2 a4 [2] cc b9 [2] ce b8 [2] d5 be [2] c9 b9 [2] d5 96 }

  condition:
    any of them
}