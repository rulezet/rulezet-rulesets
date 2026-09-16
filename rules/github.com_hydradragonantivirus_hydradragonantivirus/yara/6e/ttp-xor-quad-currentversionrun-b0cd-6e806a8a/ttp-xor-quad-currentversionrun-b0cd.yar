rule TTP_XOR_QUAD_CurrentVersionRun_b0cd {
  strings:
    $key_b0cd = { e3 a2 [2] c7 ac [2] ec 80 [2] c2 a2 [2] d6 b9 [2] d9 a3 [2] c7 be [2] c5 bf [2] de b9 [2] c2 be [2] de 91 }

  condition:
    any of them
}