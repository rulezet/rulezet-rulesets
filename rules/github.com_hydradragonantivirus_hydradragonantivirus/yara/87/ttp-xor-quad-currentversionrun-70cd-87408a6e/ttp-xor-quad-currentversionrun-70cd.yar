rule TTP_XOR_QUAD_CurrentVersionRun_70cd {
  strings:
    $key_70cd = { 23 a2 [2] 07 ac [2] 2c 80 [2] 02 a2 [2] 16 b9 [2] 19 a3 [2] 07 be [2] 05 bf [2] 1e b9 [2] 02 be [2] 1e 91 }

  condition:
    any of them
}