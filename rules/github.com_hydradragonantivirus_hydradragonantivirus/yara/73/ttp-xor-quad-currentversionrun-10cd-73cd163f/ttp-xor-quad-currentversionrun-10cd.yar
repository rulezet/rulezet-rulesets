rule TTP_XOR_QUAD_CurrentVersionRun_10cd {
  strings:
    $key_10cd = { 43 a2 [2] 67 ac [2] 4c 80 [2] 62 a2 [2] 76 b9 [2] 79 a3 [2] 67 be [2] 65 bf [2] 7e b9 [2] 62 be [2] 7e 91 }

  condition:
    any of them
}