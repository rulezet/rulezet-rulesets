rule TTP_XOR_QUAD_CurrentVersionRun_b8c2 {
  strings:
    $key_b8c2 = { eb ad [2] cf a3 [2] e4 8f [2] ca ad [2] de b6 [2] d1 ac [2] cf b1 [2] cd b0 [2] d6 b6 [2] ca b1 [2] d6 9e }

  condition:
    any of them
}