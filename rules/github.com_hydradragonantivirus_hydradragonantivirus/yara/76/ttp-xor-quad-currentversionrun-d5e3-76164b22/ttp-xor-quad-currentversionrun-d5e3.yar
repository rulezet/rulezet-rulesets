rule TTP_XOR_QUAD_CurrentVersionRun_d5e3 {
  strings:
    $key_d5e3 = { 86 8c [2] a2 82 [2] 89 ae [2] a7 8c [2] b3 97 [2] bc 8d [2] a2 90 [2] a0 91 [2] bb 97 [2] a7 90 [2] bb bf }

  condition:
    any of them
}