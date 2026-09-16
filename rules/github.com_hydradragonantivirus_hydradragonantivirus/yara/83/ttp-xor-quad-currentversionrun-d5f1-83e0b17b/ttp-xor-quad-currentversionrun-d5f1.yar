rule TTP_XOR_QUAD_CurrentVersionRun_d5f1 {
  strings:
    $key_d5f1 = { 86 9e [2] a2 90 [2] 89 bc [2] a7 9e [2] b3 85 [2] bc 9f [2] a2 82 [2] a0 83 [2] bb 85 [2] a7 82 [2] bb ad }

  condition:
    any of them
}