rule TTP_XOR_QUAD_CurrentVersionRun_6ccd {
  strings:
    $key_6ccd = { 3f a2 [2] 1b ac [2] 30 80 [2] 1e a2 [2] 0a b9 [2] 05 a3 [2] 1b be [2] 19 bf [2] 02 b9 [2] 1e be [2] 02 91 }

  condition:
    any of them
}