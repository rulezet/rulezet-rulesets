rule TTP_XOR_QUAD_CurrentVersionRun_d222 {
  strings:
    $key_d222 = { 81 4d [2] a5 43 [2] 8e 6f [2] a0 4d [2] b4 56 [2] bb 4c [2] a5 51 [2] a7 50 [2] bc 56 [2] a0 51 [2] bc 7e }

  condition:
    any of them
}