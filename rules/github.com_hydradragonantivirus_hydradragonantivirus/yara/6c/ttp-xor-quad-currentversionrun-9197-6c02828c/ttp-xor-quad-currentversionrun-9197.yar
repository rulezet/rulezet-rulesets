rule TTP_XOR_QUAD_CurrentVersionRun_9197 {
  strings:
    $key_9197 = { c2 f8 [2] e6 f6 [2] cd da [2] e3 f8 [2] f7 e3 [2] f8 f9 [2] e6 e4 [2] e4 e5 [2] ff e3 [2] e3 e4 [2] ff cb }

  condition:
    any of them
}