rule TTP_XOR_QUAD_CurrentVersionRun_edd5 {
  strings:
    $key_edd5 = { be ba [2] 9a b4 [2] b1 98 [2] 9f ba [2] 8b a1 [2] 84 bb [2] 9a a6 [2] 98 a7 [2] 83 a1 [2] 9f a6 [2] 83 89 }

  condition:
    any of them
}