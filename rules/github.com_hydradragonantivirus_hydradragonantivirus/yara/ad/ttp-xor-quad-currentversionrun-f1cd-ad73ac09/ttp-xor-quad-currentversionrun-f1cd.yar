rule TTP_XOR_QUAD_CurrentVersionRun_f1cd {
  strings:
    $key_f1cd = { a2 a2 [2] 86 ac [2] ad 80 [2] 83 a2 [2] 97 b9 [2] 98 a3 [2] 86 be [2] 84 bf [2] 9f b9 [2] 83 be [2] 9f 91 }

  condition:
    any of them
}