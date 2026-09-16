rule TTP_XOR_QUAD_CurrentVersionRun_bfc4 {
  strings:
    $key_bfc4 = { ec ab [2] c8 a5 [2] e3 89 [2] cd ab [2] d9 b0 [2] d6 aa [2] c8 b7 [2] ca b6 [2] d1 b0 [2] cd b7 [2] d1 98 }

  condition:
    any of them
}