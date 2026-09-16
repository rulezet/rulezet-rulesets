rule TTP_XOR_QUAD_CurrentVersionRun_ca80 {
  strings:
    $key_ca80 = { 99 ef [2] bd e1 [2] 96 cd [2] b8 ef [2] ac f4 [2] a3 ee [2] bd f3 [2] bf f2 [2] a4 f4 [2] b8 f3 [2] a4 dc }

  condition:
    any of them
}