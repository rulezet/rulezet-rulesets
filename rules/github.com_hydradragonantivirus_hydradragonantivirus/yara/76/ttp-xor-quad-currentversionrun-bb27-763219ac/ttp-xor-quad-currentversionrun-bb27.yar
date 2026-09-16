rule TTP_XOR_QUAD_CurrentVersionRun_bb27 {
  strings:
    $key_bb27 = { e8 48 [2] cc 46 [2] e7 6a [2] c9 48 [2] dd 53 [2] d2 49 [2] cc 54 [2] ce 55 [2] d5 53 [2] c9 54 [2] d5 7b }

  condition:
    any of them
}