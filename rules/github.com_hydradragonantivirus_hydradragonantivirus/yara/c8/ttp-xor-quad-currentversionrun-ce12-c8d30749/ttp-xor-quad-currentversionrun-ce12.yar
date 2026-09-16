rule TTP_XOR_QUAD_CurrentVersionRun_ce12 {
  strings:
    $key_ce12 = { 9d 7d [2] b9 73 [2] 92 5f [2] bc 7d [2] a8 66 [2] a7 7c [2] b9 61 [2] bb 60 [2] a0 66 [2] bc 61 [2] a0 4e }

  condition:
    any of them
}