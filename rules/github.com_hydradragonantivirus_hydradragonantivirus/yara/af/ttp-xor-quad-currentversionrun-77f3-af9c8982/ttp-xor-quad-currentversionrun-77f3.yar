rule TTP_XOR_QUAD_CurrentVersionRun_77f3 {
  strings:
    $key_77f3 = { 24 9c [2] 00 92 [2] 2b be [2] 05 9c [2] 11 87 [2] 1e 9d [2] 00 80 [2] 02 81 [2] 19 87 [2] 05 80 [2] 19 af }

  condition:
    any of them
}