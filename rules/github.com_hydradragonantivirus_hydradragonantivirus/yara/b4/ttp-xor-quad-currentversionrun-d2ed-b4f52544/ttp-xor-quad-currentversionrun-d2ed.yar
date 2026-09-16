rule TTP_XOR_QUAD_CurrentVersionRun_d2ed {
  strings:
    $key_d2ed = { 81 82 [2] a5 8c [2] 8e a0 [2] a0 82 [2] b4 99 [2] bb 83 [2] a5 9e [2] a7 9f [2] bc 99 [2] a0 9e [2] bc b1 }

  condition:
    any of them
}