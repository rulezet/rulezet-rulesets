rule TTP_XOR_QUAD_CurrentVersionRun_b1c2 {
  strings:
    $key_b1c2 = { e2 ad [2] c6 a3 [2] ed 8f [2] c3 ad [2] d7 b6 [2] d8 ac [2] c6 b1 [2] c4 b0 [2] df b6 [2] c3 b1 [2] df 9e }

  condition:
    any of them
}