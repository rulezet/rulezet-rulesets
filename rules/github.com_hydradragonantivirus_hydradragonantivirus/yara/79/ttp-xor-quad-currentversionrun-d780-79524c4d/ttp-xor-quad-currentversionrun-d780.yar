rule TTP_XOR_QUAD_CurrentVersionRun_d780 {
  strings:
    $key_d780 = { 84 ef [2] a0 e1 [2] 8b cd [2] a5 ef [2] b1 f4 [2] be ee [2] a0 f3 [2] a2 f2 [2] b9 f4 [2] a5 f3 [2] b9 dc }

  condition:
    any of them
}