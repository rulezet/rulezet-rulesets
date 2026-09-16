rule TTP_XOR_QUAD_CurrentVersionRun_b8c5 {
  strings:
    $key_b8c5 = { eb aa [2] cf a4 [2] e4 88 [2] ca aa [2] de b1 [2] d1 ab [2] cf b6 [2] cd b7 [2] d6 b1 [2] ca b6 [2] d6 99 }

  condition:
    any of them
}