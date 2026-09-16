rule TTP_XOR_QUAD_CurrentVersionRun_bfc2 {
  strings:
    $key_bfc2 = { ec ad [2] c8 a3 [2] e3 8f [2] cd ad [2] d9 b6 [2] d6 ac [2] c8 b1 [2] ca b0 [2] d1 b6 [2] cd b1 [2] d1 9e }

  condition:
    any of them
}