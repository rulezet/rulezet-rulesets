rule TTP_XOR_QUAD_CurrentVersionRun_a7f3 {
  strings:
    $key_a7f3 = { f4 9c [2] d0 92 [2] fb be [2] d5 9c [2] c1 87 [2] ce 9d [2] d0 80 [2] d2 81 [2] c9 87 [2] d5 80 [2] c9 af }

  condition:
    any of them
}