rule TTP_XOR_QUAD_CurrentVersionRun_a726 {
  strings:
    $key_a726 = { f4 49 [2] d0 47 [2] fb 6b [2] d5 49 [2] c1 52 [2] ce 48 [2] d0 55 [2] d2 54 [2] c9 52 [2] d5 55 [2] c9 7a }

  condition:
    any of them
}