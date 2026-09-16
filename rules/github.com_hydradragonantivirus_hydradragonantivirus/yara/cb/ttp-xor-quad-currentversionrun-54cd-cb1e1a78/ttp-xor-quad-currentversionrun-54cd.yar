rule TTP_XOR_QUAD_CurrentVersionRun_54cd {
  strings:
    $key_54cd = { 07 a2 [2] 23 ac [2] 08 80 [2] 26 a2 [2] 32 b9 [2] 3d a3 [2] 23 be [2] 21 bf [2] 3a b9 [2] 26 be [2] 3a 91 }

  condition:
    any of them
}