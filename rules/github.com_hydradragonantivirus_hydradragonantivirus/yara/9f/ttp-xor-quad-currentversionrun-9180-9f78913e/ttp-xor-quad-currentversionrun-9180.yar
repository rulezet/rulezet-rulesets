rule TTP_XOR_QUAD_CurrentVersionRun_9180 {
  strings:
    $key_9180 = { c2 ef [2] e6 e1 [2] cd cd [2] e3 ef [2] f7 f4 [2] f8 ee [2] e6 f3 [2] e4 f2 [2] ff f4 [2] e3 f3 [2] ff dc }

  condition:
    any of them
}