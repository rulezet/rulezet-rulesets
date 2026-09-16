rule TTP_XOR_QUAD_CurrentVersionRun_42cd {
  strings:
    $key_42cd = { 11 a2 [2] 35 ac [2] 1e 80 [2] 30 a2 [2] 24 b9 [2] 2b a3 [2] 35 be [2] 37 bf [2] 2c b9 [2] 30 be [2] 2c 91 }

  condition:
    any of them
}