rule TTP_XOR_QUAD_CurrentVersionRun_50cd {
  strings:
    $key_50cd = { 03 a2 [2] 27 ac [2] 0c 80 [2] 22 a2 [2] 36 b9 [2] 39 a3 [2] 27 be [2] 25 bf [2] 3e b9 [2] 22 be [2] 3e 91 }

  condition:
    any of them
}