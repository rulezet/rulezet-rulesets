rule TTP_XOR_QUAD_CurrentVersionRun_91d3 {
  strings:
    $key_91d3 = { c2 bc [2] e6 b2 [2] cd 9e [2] e3 bc [2] f7 a7 [2] f8 bd [2] e6 a0 [2] e4 a1 [2] ff a7 [2] e3 a0 [2] ff 8f }

  condition:
    any of them
}