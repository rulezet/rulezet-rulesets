rule TTP_XOR_QUAD_CurrentVersionRun_d262 {
  strings:
    $key_d262 = { 81 0d [2] a5 03 [2] 8e 2f [2] a0 0d [2] b4 16 [2] bb 0c [2] a5 11 [2] a7 10 [2] bc 16 [2] a0 11 [2] bc 3e }

  condition:
    any of them
}