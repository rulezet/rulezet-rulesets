rule TTP_XOR_QUAD_CurrentVersionRun_3ccd {
  strings:
    $key_3ccd = { 6f a2 [2] 4b ac [2] 60 80 [2] 4e a2 [2] 5a b9 [2] 55 a3 [2] 4b be [2] 49 bf [2] 52 b9 [2] 4e be [2] 52 91 }

  condition:
    any of them
}