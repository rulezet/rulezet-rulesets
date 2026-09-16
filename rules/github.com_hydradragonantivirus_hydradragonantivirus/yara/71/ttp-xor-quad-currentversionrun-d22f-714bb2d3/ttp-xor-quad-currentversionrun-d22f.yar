rule TTP_XOR_QUAD_CurrentVersionRun_d22f {
  strings:
    $key_d22f = { 81 40 [2] a5 4e [2] 8e 62 [2] a0 40 [2] b4 5b [2] bb 41 [2] a5 5c [2] a7 5d [2] bc 5b [2] a0 5c [2] bc 73 }

  condition:
    any of them
}