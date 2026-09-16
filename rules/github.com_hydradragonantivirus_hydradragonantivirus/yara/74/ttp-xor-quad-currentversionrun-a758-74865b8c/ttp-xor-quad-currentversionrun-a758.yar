rule TTP_XOR_QUAD_CurrentVersionRun_a758 {
  strings:
    $key_a758 = { f4 37 [2] d0 39 [2] fb 15 [2] d5 37 [2] c1 2c [2] ce 36 [2] d0 2b [2] d2 2a [2] c9 2c [2] d5 2b [2] c9 04 }

  condition:
    any of them
}