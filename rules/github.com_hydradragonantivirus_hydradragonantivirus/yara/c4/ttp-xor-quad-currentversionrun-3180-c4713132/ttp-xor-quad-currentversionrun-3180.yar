rule TTP_XOR_QUAD_CurrentVersionRun_3180 {
  strings:
    $key_3180 = { 62 ef [2] 46 e1 [2] 6d cd [2] 43 ef [2] 57 f4 [2] 58 ee [2] 46 f3 [2] 44 f2 [2] 5f f4 [2] 43 f3 [2] 5f dc }

  condition:
    any of them
}