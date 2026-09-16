rule TTP_XOR_QUAD_CurrentVersionRun_d5ef {
  strings:
    $key_d5ef = { 86 80 [2] a2 8e [2] 89 a2 [2] a7 80 [2] b3 9b [2] bc 81 [2] a2 9c [2] a0 9d [2] bb 9b [2] a7 9c [2] bb b3 }

  condition:
    any of them
}