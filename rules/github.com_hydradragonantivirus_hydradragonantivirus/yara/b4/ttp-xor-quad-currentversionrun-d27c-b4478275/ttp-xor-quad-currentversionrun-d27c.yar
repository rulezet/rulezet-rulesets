rule TTP_XOR_QUAD_CurrentVersionRun_d27c {
  strings:
    $key_d27c = { 81 13 [2] a5 1d [2] 8e 31 [2] a0 13 [2] b4 08 [2] bb 12 [2] a5 0f [2] a7 0e [2] bc 08 [2] a0 0f [2] bc 20 }

  condition:
    any of them
}