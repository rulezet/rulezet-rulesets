rule TTP_XOR_QUAD_CurrentVersionRun_a4cd {
  strings:
    $key_a4cd = { f7 a2 [2] d3 ac [2] f8 80 [2] d6 a2 [2] c2 b9 [2] cd a3 [2] d3 be [2] d1 bf [2] ca b9 [2] d6 be [2] ca 91 }

  condition:
    any of them
}