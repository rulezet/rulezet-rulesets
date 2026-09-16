rule TTP_XOR_QUAD_CurrentVersionRun_34cd {
  strings:
    $key_34cd = { 67 a2 [2] 43 ac [2] 68 80 [2] 46 a2 [2] 52 b9 [2] 5d a3 [2] 43 be [2] 41 bf [2] 5a b9 [2] 46 be [2] 5a 91 }

  condition:
    any of them
}