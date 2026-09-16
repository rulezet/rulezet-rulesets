rule TTP_XOR_QUAD_CurrentVersionRun_d6cd {
  strings:
    $key_d6cd = { 85 a2 [2] a1 ac [2] 8a 80 [2] a4 a2 [2] b0 b9 [2] bf a3 [2] a1 be [2] a3 bf [2] b8 b9 [2] a4 be [2] b8 91 }

  condition:
    any of them
}