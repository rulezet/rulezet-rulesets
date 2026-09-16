rule TTP_XOR_QUAD_CurrentVersionRun_4ccd {
  strings:
    $key_4ccd = { 1f a2 [2] 3b ac [2] 10 80 [2] 3e a2 [2] 2a b9 [2] 25 a3 [2] 3b be [2] 39 bf [2] 22 b9 [2] 3e be [2] 22 91 }

  condition:
    any of them
}