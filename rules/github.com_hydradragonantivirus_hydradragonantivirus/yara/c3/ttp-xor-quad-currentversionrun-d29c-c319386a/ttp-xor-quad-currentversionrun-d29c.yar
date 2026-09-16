rule TTP_XOR_QUAD_CurrentVersionRun_d29c {
  strings:
    $key_d29c = { 81 f3 [2] a5 fd [2] 8e d1 [2] a0 f3 [2] b4 e8 [2] bb f2 [2] a5 ef [2] a7 ee [2] bc e8 [2] a0 ef [2] bc c0 }

  condition:
    any of them
}