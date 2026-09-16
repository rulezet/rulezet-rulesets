rule TTP_XOR_QUAD_CurrentVersionRun_bbc1 {
  strings:
    $key_bbc1 = { e8 ae [2] cc a0 [2] e7 8c [2] c9 ae [2] dd b5 [2] d2 af [2] cc b2 [2] ce b3 [2] d5 b5 [2] c9 b2 [2] d5 9d }

  condition:
    any of them
}