rule TTP_XOR_QUAD_CurrentVersionRun_a727 {
  strings:
    $key_a727 = { f4 48 [2] d0 46 [2] fb 6a [2] d5 48 [2] c1 53 [2] ce 49 [2] d0 54 [2] d2 55 [2] c9 53 [2] d5 54 [2] c9 7b }

  condition:
    any of them
}