rule TTP_XOR_QUAD_CurrentVersionRun_a745 {
  strings:
    $key_a745 = { f4 2a [2] d0 24 [2] fb 08 [2] d5 2a [2] c1 31 [2] ce 2b [2] d0 36 [2] d2 37 [2] c9 31 [2] d5 36 [2] c9 19 }

  condition:
    any of them
}