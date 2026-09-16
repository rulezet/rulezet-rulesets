rule TTP_XOR_QUAD_CurrentVersionRun_26cd {
  strings:
    $key_26cd = { 75 a2 [2] 51 ac [2] 7a 80 [2] 54 a2 [2] 40 b9 [2] 4f a3 [2] 51 be [2] 53 bf [2] 48 b9 [2] 54 be [2] 48 91 }

  condition:
    any of them
}