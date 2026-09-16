rule TTP_XOR_QUAD_CurrentVersionRun_eccd {
  strings:
    $key_eccd = { bf a2 [2] 9b ac [2] b0 80 [2] 9e a2 [2] 8a b9 [2] 85 a3 [2] 9b be [2] 99 bf [2] 82 b9 [2] 9e be [2] 82 91 }

  condition:
    any of them
}