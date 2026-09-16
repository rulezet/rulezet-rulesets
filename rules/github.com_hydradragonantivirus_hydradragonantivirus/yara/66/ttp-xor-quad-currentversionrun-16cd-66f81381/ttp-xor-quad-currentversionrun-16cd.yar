rule TTP_XOR_QUAD_CurrentVersionRun_16cd {
  strings:
    $key_16cd = { 45 a2 [2] 61 ac [2] 4a 80 [2] 64 a2 [2] 70 b9 [2] 7f a3 [2] 61 be [2] 63 bf [2] 78 b9 [2] 64 be [2] 78 91 }

  condition:
    any of them
}