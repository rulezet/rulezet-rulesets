rule TTP_XOR_QUAD_CurrentVersionRun_d2fc {
  strings:
    $key_d2fc = { 81 93 [2] a5 9d [2] 8e b1 [2] a0 93 [2] b4 88 [2] bb 92 [2] a5 8f [2] a7 8e [2] bc 88 [2] a0 8f [2] bc a0 }

  condition:
    any of them
}