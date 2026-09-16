rule TTP_XOR_QUAD_CurrentVersionRun_a744 {
  strings:
    $key_a744 = { f4 2b [2] d0 25 [2] fb 09 [2] d5 2b [2] c1 30 [2] ce 2a [2] d0 37 [2] d2 36 [2] c9 30 [2] d5 37 [2] c9 18 }

  condition:
    any of them
}