rule TTP_XOR_QUAD_CurrentVersionRun_d232 {
  strings:
    $key_d232 = { 81 5d [2] a5 53 [2] 8e 7f [2] a0 5d [2] b4 46 [2] bb 5c [2] a5 41 [2] a7 40 [2] bc 46 [2] a0 41 [2] bc 6e }

  condition:
    any of them
}