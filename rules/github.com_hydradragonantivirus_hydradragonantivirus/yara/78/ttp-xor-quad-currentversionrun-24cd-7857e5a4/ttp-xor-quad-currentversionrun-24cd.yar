rule TTP_XOR_QUAD_CurrentVersionRun_24cd {
  strings:
    $key_24cd = { 77 a2 [2] 53 ac [2] 78 80 [2] 56 a2 [2] 42 b9 [2] 4d a3 [2] 53 be [2] 51 bf [2] 4a b9 [2] 56 be [2] 4a 91 }

  condition:
    any of them
}