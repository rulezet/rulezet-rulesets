rule TTP_XOR_QUAD_CurrentVersionRun_a763 {
  strings:
    $key_a763 = { f4 0c [2] d0 02 [2] fb 2e [2] d5 0c [2] c1 17 [2] ce 0d [2] d0 10 [2] d2 11 [2] c9 17 [2] d5 10 [2] c9 3f }

  condition:
    any of them
}