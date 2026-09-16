rule TTP_XOR_QUAD_CurrentVersionRun_4680 {
  strings:
    $key_4680 = { 15 ef [2] 31 e1 [2] 1a cd [2] 34 ef [2] 20 f4 [2] 2f ee [2] 31 f3 [2] 33 f2 [2] 28 f4 [2] 34 f3 [2] 28 dc }

  condition:
    any of them
}