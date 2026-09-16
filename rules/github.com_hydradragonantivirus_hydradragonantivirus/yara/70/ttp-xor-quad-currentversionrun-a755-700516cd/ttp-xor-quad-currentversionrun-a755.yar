rule TTP_XOR_QUAD_CurrentVersionRun_a755 {
  strings:
    $key_a755 = { f4 3a [2] d0 34 [2] fb 18 [2] d5 3a [2] c1 21 [2] ce 3b [2] d0 26 [2] d2 27 [2] c9 21 [2] d5 26 [2] c9 09 }

  condition:
    any of them
}