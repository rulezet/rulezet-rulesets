rule TTP_XOR_QUAD_CurrentVersionRun_cefd {
  strings:
    $key_cefd = { 9d 92 [2] b9 9c [2] 92 b0 [2] bc 92 [2] a8 89 [2] a7 93 [2] b9 8e [2] bb 8f [2] a0 89 [2] bc 8e [2] a0 a1 }

  condition:
    any of them
}