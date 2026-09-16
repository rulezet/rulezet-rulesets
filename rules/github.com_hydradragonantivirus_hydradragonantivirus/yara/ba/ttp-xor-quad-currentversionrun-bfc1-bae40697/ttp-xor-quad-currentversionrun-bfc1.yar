rule TTP_XOR_QUAD_CurrentVersionRun_bfc1 {
  strings:
    $key_bfc1 = { ec ae [2] c8 a0 [2] e3 8c [2] cd ae [2] d9 b5 [2] d6 af [2] c8 b2 [2] ca b3 [2] d1 b5 [2] cd b2 [2] d1 9d }

  condition:
    any of them
}