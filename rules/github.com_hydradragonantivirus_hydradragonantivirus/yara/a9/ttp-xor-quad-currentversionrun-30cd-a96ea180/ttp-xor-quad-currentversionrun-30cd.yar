rule TTP_XOR_QUAD_CurrentVersionRun_30cd {
  strings:
    $key_30cd = { 63 a2 [2] 47 ac [2] 6c 80 [2] 42 a2 [2] 56 b9 [2] 59 a3 [2] 47 be [2] 45 bf [2] 5e b9 [2] 42 be [2] 5e 91 }

  condition:
    any of them
}