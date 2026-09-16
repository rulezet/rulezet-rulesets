rule TTP_XOR_QUAD_CurrentVersionRun_4df3 {
  strings:
    $key_4df3 = { 1e 9c [2] 3a 92 [2] 11 be [2] 3f 9c [2] 2b 87 [2] 24 9d [2] 3a 80 [2] 38 81 [2] 23 87 [2] 3f 80 [2] 23 af }

  condition:
    any of them
}