rule TTP_XOR_QUAD_CurrentVersionRun_d224 {
  strings:
    $key_d224 = { 81 4b [2] a5 45 [2] 8e 69 [2] a0 4b [2] b4 50 [2] bb 4a [2] a5 57 [2] a7 56 [2] bc 50 [2] a0 57 [2] bc 78 }

  condition:
    any of them
}