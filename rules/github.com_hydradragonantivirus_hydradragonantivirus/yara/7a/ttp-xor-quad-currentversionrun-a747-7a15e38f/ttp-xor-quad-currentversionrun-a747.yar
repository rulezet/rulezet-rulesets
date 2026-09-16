rule TTP_XOR_QUAD_CurrentVersionRun_a747 {
  strings:
    $key_a747 = { f4 28 [2] d0 26 [2] fb 0a [2] d5 28 [2] c1 33 [2] ce 29 [2] d0 34 [2] d2 35 [2] c9 33 [2] d5 34 [2] c9 1b }

  condition:
    any of them
}