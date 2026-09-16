rule TTP_XOR_QUAD_CurrentVersionRun_8d9c {
  strings:
    $key_8d9c = { de f3 [2] fa fd [2] d1 d1 [2] ff f3 [2] eb e8 [2] e4 f2 [2] fa ef [2] f8 ee [2] e3 e8 [2] ff ef [2] e3 c0 }

  condition:
    any of them
}