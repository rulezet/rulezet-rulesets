rule TTP_XOR_QUAD_CurrentVersionRun_67cd {
  strings:
    $key_67cd = { 34 a2 [2] 10 ac [2] 3b 80 [2] 15 a2 [2] 01 b9 [2] 0e a3 [2] 10 be [2] 12 bf [2] 09 b9 [2] 15 be [2] 09 91 }

  condition:
    any of them
}