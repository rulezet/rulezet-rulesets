rule TTP_XOR_QUAD_CurrentVersionRun_bbc9 {
  strings:
    $key_bbc9 = { e8 a6 [2] cc a8 [2] e7 84 [2] c9 a6 [2] dd bd [2] d2 a7 [2] cc ba [2] ce bb [2] d5 bd [2] c9 ba [2] d5 95 }

  condition:
    any of them
}