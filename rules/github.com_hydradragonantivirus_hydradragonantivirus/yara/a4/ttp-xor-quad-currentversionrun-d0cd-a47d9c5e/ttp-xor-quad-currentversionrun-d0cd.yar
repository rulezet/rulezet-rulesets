rule TTP_XOR_QUAD_CurrentVersionRun_d0cd {
  strings:
    $key_d0cd = { 83 a2 [2] a7 ac [2] 8c 80 [2] a2 a2 [2] b6 b9 [2] b9 a3 [2] a7 be [2] a5 bf [2] be b9 [2] a2 be [2] be 91 }

  condition:
    any of them
}