rule TTP_XOR_QUAD_CurrentVersionRun_d5ed {
  strings:
    $key_d5ed = { 86 82 [2] a2 8c [2] 89 a0 [2] a7 82 [2] b3 99 [2] bc 83 [2] a2 9e [2] a0 9f [2] bb 99 [2] a7 9e [2] bb b1 }

  condition:
    any of them
}