rule TTP_XOR_QUAD_CurrentVersionRun_d5fc {
  strings:
    $key_d5fc = { 86 93 [2] a2 9d [2] 89 b1 [2] a7 93 [2] b3 88 [2] bc 92 [2] a2 8f [2] a0 8e [2] bb 88 [2] a7 8f [2] bb a0 }

  condition:
    any of them
}