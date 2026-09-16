rule TTP_XOR_QUAD_CurrentVersionRun_c5cd {
  strings:
    $key_c5cd = { 96 a2 [2] b2 ac [2] 99 80 [2] b7 a2 [2] a3 b9 [2] ac a3 [2] b2 be [2] b0 bf [2] ab b9 [2] b7 be [2] ab 91 }

  condition:
    any of them
}