rule TTP_XOR_QUAD_CurrentVersionRun_d5ee {
  strings:
    $key_d5ee = { 86 81 [2] a2 8f [2] 89 a3 [2] a7 81 [2] b3 9a [2] bc 80 [2] a2 9d [2] a0 9c [2] bb 9a [2] a7 9d [2] bb b2 }

  condition:
    any of them
}