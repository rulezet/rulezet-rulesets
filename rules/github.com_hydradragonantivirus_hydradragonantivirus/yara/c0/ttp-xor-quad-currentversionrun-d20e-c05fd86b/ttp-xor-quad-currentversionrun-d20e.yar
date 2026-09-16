rule TTP_XOR_QUAD_CurrentVersionRun_d20e {
  strings:
    $key_d20e = { 81 61 [2] a5 6f [2] 8e 43 [2] a0 61 [2] b4 7a [2] bb 60 [2] a5 7d [2] a7 7c [2] bc 7a [2] a0 7d [2] bc 52 }

  condition:
    any of them
}