rule TTP_XOR_QUAD_CurrentVersionRun_c3cd {
  strings:
    $key_c3cd = { 90 a2 [2] b4 ac [2] 9f 80 [2] b1 a2 [2] a5 b9 [2] aa a3 [2] b4 be [2] b6 bf [2] ad b9 [2] b1 be [2] ad 91 }

  condition:
    any of them
}