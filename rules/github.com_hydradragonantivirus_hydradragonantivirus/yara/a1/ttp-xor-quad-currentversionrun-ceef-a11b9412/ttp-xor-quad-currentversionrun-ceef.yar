rule TTP_XOR_QUAD_CurrentVersionRun_ceef {
  strings:
    $key_ceef = { 9d 80 [2] b9 8e [2] 92 a2 [2] bc 80 [2] a8 9b [2] a7 81 [2] b9 9c [2] bb 9d [2] a0 9b [2] bc 9c [2] a0 b3 }

  condition:
    any of them
}