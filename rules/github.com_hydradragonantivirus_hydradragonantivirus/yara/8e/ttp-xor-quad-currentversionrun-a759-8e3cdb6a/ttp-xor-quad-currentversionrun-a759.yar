rule TTP_XOR_QUAD_CurrentVersionRun_a759 {
  strings:
    $key_a759 = { f4 36 [2] d0 38 [2] fb 14 [2] d5 36 [2] c1 2d [2] ce 37 [2] d0 2a [2] d2 2b [2] c9 2d [2] d5 2a [2] c9 05 }

  condition:
    any of them
}