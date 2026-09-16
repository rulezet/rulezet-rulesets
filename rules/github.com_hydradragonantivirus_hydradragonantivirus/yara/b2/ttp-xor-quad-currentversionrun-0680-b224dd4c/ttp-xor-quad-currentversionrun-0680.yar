rule TTP_XOR_QUAD_CurrentVersionRun_0680 {
  strings:
    $key_0680 = { 55 ef [2] 71 e1 [2] 5a cd [2] 74 ef [2] 60 f4 [2] 6f ee [2] 71 f3 [2] 73 f2 [2] 68 f4 [2] 74 f3 [2] 68 dc }

  condition:
    any of them
}