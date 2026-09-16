rule TTP_XOR_QUAD_CurrentVersionRun_a743 {
  strings:
    $key_a743 = { f4 2c [2] d0 22 [2] fb 0e [2] d5 2c [2] c1 37 [2] ce 2d [2] d0 30 [2] d2 31 [2] c9 37 [2] d5 30 [2] c9 1f }

  condition:
    any of them
}