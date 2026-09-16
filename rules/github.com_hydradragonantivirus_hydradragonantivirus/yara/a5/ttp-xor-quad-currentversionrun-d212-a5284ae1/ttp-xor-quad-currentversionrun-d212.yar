rule TTP_XOR_QUAD_CurrentVersionRun_d212 {
  strings:
    $key_d212 = { 81 7d [2] a5 73 [2] 8e 5f [2] a0 7d [2] b4 66 [2] bb 7c [2] a5 61 [2] a7 60 [2] bc 66 [2] a0 61 [2] bc 4e }

  condition:
    any of them
}