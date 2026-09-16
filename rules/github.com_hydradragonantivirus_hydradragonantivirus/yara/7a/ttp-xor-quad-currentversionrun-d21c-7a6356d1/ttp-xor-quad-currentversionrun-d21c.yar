rule TTP_XOR_QUAD_CurrentVersionRun_d21c {
  strings:
    $key_d21c = { 81 73 [2] a5 7d [2] 8e 51 [2] a0 73 [2] b4 68 [2] bb 72 [2] a5 6f [2] a7 6e [2] bc 68 [2] a0 6f [2] bc 40 }

  condition:
    any of them
}