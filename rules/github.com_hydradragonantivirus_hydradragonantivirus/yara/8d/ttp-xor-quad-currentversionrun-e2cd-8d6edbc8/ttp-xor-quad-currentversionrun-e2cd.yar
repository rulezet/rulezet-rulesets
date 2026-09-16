rule TTP_XOR_QUAD_CurrentVersionRun_e2cd {
  strings:
    $key_e2cd = { b1 a2 [2] 95 ac [2] be 80 [2] 90 a2 [2] 84 b9 [2] 8b a3 [2] 95 be [2] 97 bf [2] 8c b9 [2] 90 be [2] 8c 91 }

  condition:
    any of them
}