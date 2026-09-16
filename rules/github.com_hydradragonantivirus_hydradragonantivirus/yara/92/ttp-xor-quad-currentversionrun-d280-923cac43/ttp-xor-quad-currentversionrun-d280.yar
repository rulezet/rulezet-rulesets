rule TTP_XOR_QUAD_CurrentVersionRun_d280 {
  strings:
    $key_d280 = { 81 ef [2] a5 e1 [2] 8e cd [2] a0 ef [2] b4 f4 [2] bb ee [2] a5 f3 [2] a7 f2 [2] bc f4 [2] a0 f3 [2] bc dc }

  condition:
    any of them
}