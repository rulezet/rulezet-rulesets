rule TTP_XOR_QUAD_CurrentVersionRun_7680 {
  strings:
    $key_7680 = { 25 ef [2] 01 e1 [2] 2a cd [2] 04 ef [2] 10 f4 [2] 1f ee [2] 01 f3 [2] 03 f2 [2] 18 f4 [2] 04 f3 [2] 18 dc }

  condition:
    any of them
}