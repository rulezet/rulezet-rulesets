rule TTP_XOR_QUAD_CurrentVersionRun_07cd {
  strings:
    $key_07cd = { 54 a2 [2] 70 ac [2] 5b 80 [2] 75 a2 [2] 61 b9 [2] 6e a3 [2] 70 be [2] 72 bf [2] 69 b9 [2] 75 be [2] 69 91 }

  condition:
    any of them
}