rule TTP_XOR_QUAD_CurrentVersionRun_c2cd {
  strings:
    $key_c2cd = { 91 a2 [2] b5 ac [2] 9e 80 [2] b0 a2 [2] a4 b9 [2] ab a3 [2] b5 be [2] b7 bf [2] ac b9 [2] b0 be [2] ac 91 }

  condition:
    any of them
}