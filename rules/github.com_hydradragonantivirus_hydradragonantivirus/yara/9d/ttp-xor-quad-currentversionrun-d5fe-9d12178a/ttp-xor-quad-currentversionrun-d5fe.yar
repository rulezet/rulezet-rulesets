rule TTP_XOR_QUAD_CurrentVersionRun_d5fe {
  strings:
    $key_d5fe = { 86 91 [2] a2 9f [2] 89 b3 [2] a7 91 [2] b3 8a [2] bc 90 [2] a2 8d [2] a0 8c [2] bb 8a [2] a7 8d [2] bb a2 }

  condition:
    any of them
}