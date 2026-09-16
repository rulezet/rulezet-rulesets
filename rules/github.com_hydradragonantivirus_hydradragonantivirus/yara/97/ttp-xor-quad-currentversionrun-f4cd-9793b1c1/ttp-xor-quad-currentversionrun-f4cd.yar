rule TTP_XOR_QUAD_CurrentVersionRun_f4cd {
  strings:
    $key_f4cd = { a7 a2 [2] 83 ac [2] a8 80 [2] 86 a2 [2] 92 b9 [2] 9d a3 [2] 83 be [2] 81 bf [2] 9a b9 [2] 86 be [2] 9a 91 }

  condition:
    any of them
}