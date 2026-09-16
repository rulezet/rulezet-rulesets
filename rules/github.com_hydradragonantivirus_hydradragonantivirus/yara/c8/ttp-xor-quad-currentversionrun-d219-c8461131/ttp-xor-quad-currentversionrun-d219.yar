rule TTP_XOR_QUAD_CurrentVersionRun_d219 {
  strings:
    $key_d219 = { 81 76 [2] a5 78 [2] 8e 54 [2] a0 76 [2] b4 6d [2] bb 77 [2] a5 6a [2] a7 6b [2] bc 6d [2] a0 6a [2] bc 45 }

  condition:
    any of them
}