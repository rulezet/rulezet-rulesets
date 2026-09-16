rule TTP_XOR_QUAD_CurrentVersionRun_72cd {
  strings:
    $key_72cd = { 21 a2 [2] 05 ac [2] 2e 80 [2] 00 a2 [2] 14 b9 [2] 1b a3 [2] 05 be [2] 07 bf [2] 1c b9 [2] 00 be [2] 1c 91 }

  condition:
    any of them
}