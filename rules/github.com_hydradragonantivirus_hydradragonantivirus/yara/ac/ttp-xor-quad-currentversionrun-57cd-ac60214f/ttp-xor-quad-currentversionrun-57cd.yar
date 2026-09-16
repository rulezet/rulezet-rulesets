rule TTP_XOR_QUAD_CurrentVersionRun_57cd {
  strings:
    $key_57cd = { 04 a2 [2] 20 ac [2] 0b 80 [2] 25 a2 [2] 31 b9 [2] 3e a3 [2] 20 be [2] 22 bf [2] 39 b9 [2] 25 be [2] 39 91 }

  condition:
    any of them
}