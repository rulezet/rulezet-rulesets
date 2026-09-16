rule TTP_XOR_QUAD_CurrentVersionRun_40cd {
  strings:
    $key_40cd = { 13 a2 [2] 37 ac [2] 1c 80 [2] 32 a2 [2] 26 b9 [2] 29 a3 [2] 37 be [2] 35 bf [2] 2e b9 [2] 32 be [2] 2e 91 }

  condition:
    any of them
}