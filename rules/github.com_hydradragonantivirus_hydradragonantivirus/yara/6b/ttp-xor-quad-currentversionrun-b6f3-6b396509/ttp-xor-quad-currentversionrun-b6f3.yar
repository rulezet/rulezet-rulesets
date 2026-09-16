rule TTP_XOR_QUAD_CurrentVersionRun_b6f3 {
  strings:
    $key_b6f3 = { e5 9c [2] c1 92 [2] ea be [2] c4 9c [2] d0 87 [2] df 9d [2] c1 80 [2] c3 81 [2] d8 87 [2] c4 80 [2] d8 af }

  condition:
    any of them
}