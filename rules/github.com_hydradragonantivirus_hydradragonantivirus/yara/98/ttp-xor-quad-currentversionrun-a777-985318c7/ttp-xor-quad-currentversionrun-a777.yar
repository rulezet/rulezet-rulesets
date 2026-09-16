rule TTP_XOR_QUAD_CurrentVersionRun_a777 {
  strings:
    $key_a777 = { f4 18 [2] d0 16 [2] fb 3a [2] d5 18 [2] c1 03 [2] ce 19 [2] d0 04 [2] d2 05 [2] c9 03 [2] d5 04 [2] c9 2b }

  condition:
    any of them
}