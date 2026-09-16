rule TTP_XOR_QUAD_CurrentVersionRun_a774 {
  strings:
    $key_a774 = { f4 1b [2] d0 15 [2] fb 39 [2] d5 1b [2] c1 00 [2] ce 1a [2] d0 07 [2] d2 06 [2] c9 00 [2] d5 07 [2] c9 28 }

  condition:
    any of them
}