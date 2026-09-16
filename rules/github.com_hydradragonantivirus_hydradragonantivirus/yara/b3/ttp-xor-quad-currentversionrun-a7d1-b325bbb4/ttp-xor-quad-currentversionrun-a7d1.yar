rule TTP_XOR_QUAD_CurrentVersionRun_a7d1 {
  strings:
    $key_a7d1 = { f4 be [2] d0 b0 [2] fb 9c [2] d5 be [2] c1 a5 [2] ce bf [2] d0 a2 [2] d2 a3 [2] c9 a5 [2] d5 a2 [2] c9 8d }

  condition:
    any of them
}