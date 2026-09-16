rule TTP_XOR_QUAD_CurrentVersionRun_bbc2 {
  strings:
    $key_bbc2 = { e8 ad [2] cc a3 [2] e7 8f [2] c9 ad [2] dd b6 [2] d2 ac [2] cc b1 [2] ce b0 [2] d5 b6 [2] c9 b1 [2] d5 9e }

  condition:
    any of them
}