rule TTP_XOR_QUAD_CurrentVersionRun_d208 {
  strings:
    $key_d208 = { 81 67 [2] a5 69 [2] 8e 45 [2] a0 67 [2] b4 7c [2] bb 66 [2] a5 7b [2] a7 7a [2] bc 7c [2] a0 7b [2] bc 54 }

  condition:
    any of them
}