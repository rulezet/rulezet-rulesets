rule TTP_XOR_QUAD_CurrentVersionRun_d562 {
  strings:
    $key_d562 = { 86 0d [2] a2 03 [2] 89 2f [2] a7 0d [2] b3 16 [2] bc 0c [2] a2 11 [2] a0 10 [2] bb 16 [2] a7 11 [2] bb 3e }

  condition:
    any of them
}