rule TTP_XOR_QUAD_CurrentVersionRun_a0cd {
  strings:
    $key_a0cd = { f3 a2 [2] d7 ac [2] fc 80 [2] d2 a2 [2] c6 b9 [2] c9 a3 [2] d7 be [2] d5 bf [2] ce b9 [2] d2 be [2] ce 91 }

  condition:
    any of them
}