rule TTP_XOR_QUAD_CurrentVersionRun_b6c2 {
  strings:
    $key_b6c2 = { e5 ad [2] c1 a3 [2] ea 8f [2] c4 ad [2] d0 b6 [2] df ac [2] c1 b1 [2] c3 b0 [2] d8 b6 [2] c4 b1 [2] d8 9e }

  condition:
    any of them
}