rule TTP_XOR_QUAD_CurrentVersionRun_d5ff {
  strings:
    $key_d5ff = { 86 90 [2] a2 9e [2] 89 b2 [2] a7 90 [2] b3 8b [2] bc 91 [2] a2 8c [2] a0 8d [2] bb 8b [2] a7 8c [2] bb a3 }

  condition:
    any of them
}