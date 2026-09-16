rule TTP_XOR_QUAD_CurrentVersionRun_a737 {
  strings:
    $key_a737 = { f4 58 [2] d0 56 [2] fb 7a [2] d5 58 [2] c1 43 [2] ce 59 [2] d0 44 [2] d2 45 [2] c9 43 [2] d5 44 [2] c9 6b }

  condition:
    any of them
}