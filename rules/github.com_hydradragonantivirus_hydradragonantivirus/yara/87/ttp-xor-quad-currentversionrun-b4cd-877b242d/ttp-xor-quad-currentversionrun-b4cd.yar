rule TTP_XOR_QUAD_CurrentVersionRun_b4cd {
  strings:
    $key_b4cd = { e7 a2 [2] c3 ac [2] e8 80 [2] c6 a2 [2] d2 b9 [2] dd a3 [2] c3 be [2] c1 bf [2] da b9 [2] c6 be [2] da 91 }

  condition:
    any of them
}