rule TTP_XOR_QUAD_CurrentVersionRun_f3cd {
  strings:
    $key_f3cd = { a0 a2 [2] 84 ac [2] af 80 [2] 81 a2 [2] 95 b9 [2] 9a a3 [2] 84 be [2] 86 bf [2] 9d b9 [2] 81 be [2] 9d 91 }

  condition:
    any of them
}