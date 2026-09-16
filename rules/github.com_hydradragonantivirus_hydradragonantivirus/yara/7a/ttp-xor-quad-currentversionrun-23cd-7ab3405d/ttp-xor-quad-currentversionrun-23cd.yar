rule TTP_XOR_QUAD_CurrentVersionRun_23cd {
  strings:
    $key_23cd = { 70 a2 [2] 54 ac [2] 7f 80 [2] 51 a2 [2] 45 b9 [2] 4a a3 [2] 54 be [2] 56 bf [2] 4d b9 [2] 51 be [2] 4d 91 }

  condition:
    any of them
}