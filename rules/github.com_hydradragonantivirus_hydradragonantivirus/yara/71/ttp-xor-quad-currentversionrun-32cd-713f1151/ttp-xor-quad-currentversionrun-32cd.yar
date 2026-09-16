rule TTP_XOR_QUAD_CurrentVersionRun_32cd {
  strings:
    $key_32cd = { 61 a2 [2] 45 ac [2] 6e 80 [2] 40 a2 [2] 54 b9 [2] 5b a3 [2] 45 be [2] 47 bf [2] 5c b9 [2] 40 be [2] 5c 91 }

  condition:
    any of them
}