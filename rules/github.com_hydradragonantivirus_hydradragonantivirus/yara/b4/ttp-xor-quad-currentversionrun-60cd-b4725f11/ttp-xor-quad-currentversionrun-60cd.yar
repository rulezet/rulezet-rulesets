rule TTP_XOR_QUAD_CurrentVersionRun_60cd {
  strings:
    $key_60cd = { 33 a2 [2] 17 ac [2] 3c 80 [2] 12 a2 [2] 06 b9 [2] 09 a3 [2] 17 be [2] 15 bf [2] 0e b9 [2] 12 be [2] 0e 91 }

  condition:
    any of them
}