rule TTP_XOR_QUAD_CurrentVersionRun_a2cd {
  strings:
    $key_a2cd = { f1 a2 [2] d5 ac [2] fe 80 [2] d0 a2 [2] c4 b9 [2] cb a3 [2] d5 be [2] d7 bf [2] cc b9 [2] d0 be [2] cc 91 }

  condition:
    any of them
}