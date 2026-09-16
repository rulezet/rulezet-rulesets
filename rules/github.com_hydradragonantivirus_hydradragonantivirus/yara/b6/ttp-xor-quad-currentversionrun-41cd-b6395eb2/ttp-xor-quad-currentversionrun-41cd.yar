rule TTP_XOR_QUAD_CurrentVersionRun_41cd {
  strings:
    $key_41cd = { 12 a2 [2] 36 ac [2] 1d 80 [2] 33 a2 [2] 27 b9 [2] 28 a3 [2] 36 be [2] 34 bf [2] 2f b9 [2] 33 be [2] 2f 91 }

  condition:
    any of them
}