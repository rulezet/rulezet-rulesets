rule TTP_XOR_QUAD_CurrentVersionRun_4481 {
  strings:
    $key_4481 = { 17 ee [2] 33 e0 [2] 18 cc [2] 36 ee [2] 22 f5 [2] 2d ef [2] 33 f2 [2] 31 f3 [2] 2a f5 [2] 36 f2 [2] 2a dd }

  condition:
    any of them
}