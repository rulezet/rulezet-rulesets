rule TTP_XOR_QUAD_CurrentVersionRun_55cd {
  strings:
    $key_55cd = { 06 a2 [2] 22 ac [2] 09 80 [2] 27 a2 [2] 33 b9 [2] 3c a3 [2] 22 be [2] 20 bf [2] 3b b9 [2] 27 be [2] 3b 91 }

  condition:
    any of them
}