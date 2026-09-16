rule TTP_XOR_QUAD_CurrentVersionRun_43cd {
  strings:
    $key_43cd = { 10 a2 [2] 34 ac [2] 1f 80 [2] 31 a2 [2] 25 b9 [2] 2a a3 [2] 34 be [2] 36 bf [2] 2d b9 [2] 31 be [2] 2d 91 }

  condition:
    any of them
}