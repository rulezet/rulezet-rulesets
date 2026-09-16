rule TTP_XOR_QUAD_CurrentVersionRun_e3cd {
  strings:
    $key_e3cd = { b0 a2 [2] 94 ac [2] bf 80 [2] 91 a2 [2] 85 b9 [2] 8a a3 [2] 94 be [2] 96 bf [2] 8d b9 [2] 91 be [2] 8d 91 }

  condition:
    any of them
}