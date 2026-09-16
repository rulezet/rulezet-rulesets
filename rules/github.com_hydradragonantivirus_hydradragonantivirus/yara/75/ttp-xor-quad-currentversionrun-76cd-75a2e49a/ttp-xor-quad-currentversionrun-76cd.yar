rule TTP_XOR_QUAD_CurrentVersionRun_76cd {
  strings:
    $key_76cd = { 25 a2 [2] 01 ac [2] 2a 80 [2] 04 a2 [2] 10 b9 [2] 1f a3 [2] 01 be [2] 03 bf [2] 18 b9 [2] 04 be [2] 18 91 }

  condition:
    any of them
}