rule TTP_XOR_QUAD_CurrentVersionRun_e5cd {
  strings:
    $key_e5cd = { b6 a2 [2] 92 ac [2] b9 80 [2] 97 a2 [2] 83 b9 [2] 8c a3 [2] 92 be [2] 90 bf [2] 8b b9 [2] 97 be [2] 8b 91 }

  condition:
    any of them
}