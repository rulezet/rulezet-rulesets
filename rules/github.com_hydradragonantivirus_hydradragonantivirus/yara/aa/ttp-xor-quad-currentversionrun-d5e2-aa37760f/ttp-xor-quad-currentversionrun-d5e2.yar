rule TTP_XOR_QUAD_CurrentVersionRun_d5e2 {
  strings:
    $key_d5e2 = { 86 8d [2] a2 83 [2] 89 af [2] a7 8d [2] b3 96 [2] bc 8c [2] a2 91 [2] a0 90 [2] bb 96 [2] a7 91 [2] bb be }

  condition:
    any of them
}