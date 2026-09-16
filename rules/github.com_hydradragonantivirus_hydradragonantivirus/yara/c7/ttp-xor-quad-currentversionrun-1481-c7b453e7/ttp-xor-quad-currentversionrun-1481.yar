rule TTP_XOR_QUAD_CurrentVersionRun_1481 {
  strings:
    $key_1481 = { 47 ee [2] 63 e0 [2] 48 cc [2] 66 ee [2] 72 f5 [2] 7d ef [2] 63 f2 [2] 61 f3 [2] 7a f5 [2] 66 f2 [2] 7a dd }

  condition:
    any of them
}