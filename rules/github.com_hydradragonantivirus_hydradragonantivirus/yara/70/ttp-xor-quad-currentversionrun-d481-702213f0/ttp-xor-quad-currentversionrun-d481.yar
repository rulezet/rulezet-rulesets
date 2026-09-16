rule TTP_XOR_QUAD_CurrentVersionRun_d481 {
  strings:
    $key_d481 = { 87 ee [2] a3 e0 [2] 88 cc [2] a6 ee [2] b2 f5 [2] bd ef [2] a3 f2 [2] a1 f3 [2] ba f5 [2] a6 f2 [2] ba dd }

  condition:
    any of them
}