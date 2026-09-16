rule TTP_XOR_QUAD_CurrentVersionRun_d5cd {
  strings:
    $key_d5cd = { 86 a2 [2] a2 ac [2] 89 80 [2] a7 a2 [2] b3 b9 [2] bc a3 [2] a2 be [2] a0 bf [2] bb b9 [2] a7 be [2] bb 91 }

  condition:
    any of them
}