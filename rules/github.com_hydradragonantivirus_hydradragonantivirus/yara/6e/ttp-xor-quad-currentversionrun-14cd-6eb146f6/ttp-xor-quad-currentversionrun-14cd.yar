rule TTP_XOR_QUAD_CurrentVersionRun_14cd {
  strings:
    $key_14cd = { 47 a2 [2] 63 ac [2] 48 80 [2] 66 a2 [2] 72 b9 [2] 7d a3 [2] 63 be [2] 61 bf [2] 7a b9 [2] 66 be [2] 7a 91 }

  condition:
    any of them
}