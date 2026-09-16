rule TTP_XOR_QUAD_CurrentVersionRun_d27f {
  strings:
    $key_d27f = { 81 10 [2] a5 1e [2] 8e 32 [2] a0 10 [2] b4 0b [2] bb 11 [2] a5 0c [2] a7 0d [2] bc 0b [2] a0 0c [2] bc 23 }

  condition:
    any of them
}