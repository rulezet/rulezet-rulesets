rule TTP_XOR_QUAD_CurrentVersionRun_bbc7 {
  strings:
    $key_bbc7 = { e8 a8 [2] cc a6 [2] e7 8a [2] c9 a8 [2] dd b3 [2] d2 a9 [2] cc b4 [2] ce b5 [2] d5 b3 [2] c9 b4 [2] d5 9b }

  condition:
    any of them
}