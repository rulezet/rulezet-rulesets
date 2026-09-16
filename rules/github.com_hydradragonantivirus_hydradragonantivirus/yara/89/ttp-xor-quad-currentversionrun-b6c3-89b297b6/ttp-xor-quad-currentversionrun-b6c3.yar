rule TTP_XOR_QUAD_CurrentVersionRun_b6c3 {
  strings:
    $key_b6c3 = { e5 ac [2] c1 a2 [2] ea 8e [2] c4 ac [2] d0 b7 [2] df ad [2] c1 b0 [2] c3 b1 [2] d8 b7 [2] c4 b0 [2] d8 9f }

  condition:
    any of them
}