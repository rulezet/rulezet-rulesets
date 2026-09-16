rule TTP_XOR_QUAD_CurrentVersionRun_b8c4 {
  strings:
    $key_b8c4 = { eb ab [2] cf a5 [2] e4 89 [2] ca ab [2] de b0 [2] d1 aa [2] cf b7 [2] cd b6 [2] d6 b0 [2] ca b7 [2] d6 98 }

  condition:
    any of them
}