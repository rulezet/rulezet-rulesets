rule TTP_XOR_QUAD_CurrentVersionRun_63cd {
  strings:
    $key_63cd = { 30 a2 [2] 14 ac [2] 3f 80 [2] 11 a2 [2] 05 b9 [2] 0a a3 [2] 14 be [2] 16 bf [2] 0d b9 [2] 11 be [2] 0d 91 }

  condition:
    any of them
}