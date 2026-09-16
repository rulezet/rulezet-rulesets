rule TTP_XOR_QUAD_CurrentVersionRun_d7cd {
  strings:
    $key_d7cd = { 84 a2 [2] a0 ac [2] 8b 80 [2] a5 a2 [2] b1 b9 [2] be a3 [2] a0 be [2] a2 bf [2] b9 b9 [2] a5 be [2] b9 91 }

  condition:
    any of them
}