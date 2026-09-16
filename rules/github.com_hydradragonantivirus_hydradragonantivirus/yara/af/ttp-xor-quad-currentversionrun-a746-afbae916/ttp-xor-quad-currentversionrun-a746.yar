rule TTP_XOR_QUAD_CurrentVersionRun_a746 {
  strings:
    $key_a746 = { f4 29 [2] d0 27 [2] fb 0b [2] d5 29 [2] c1 32 [2] ce 28 [2] d0 35 [2] d2 34 [2] c9 32 [2] d5 35 [2] c9 1a }

  condition:
    any of them
}