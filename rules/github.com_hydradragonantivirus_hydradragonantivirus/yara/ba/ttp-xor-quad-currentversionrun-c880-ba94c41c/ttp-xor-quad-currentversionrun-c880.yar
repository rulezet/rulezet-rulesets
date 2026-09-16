rule TTP_XOR_QUAD_CurrentVersionRun_c880 {
  strings:
    $key_c880 = { 9b ef [2] bf e1 [2] 94 cd [2] ba ef [2] ae f4 [2] a1 ee [2] bf f3 [2] bd f2 [2] a6 f4 [2] ba f3 [2] a6 dc }

  condition:
    any of them
}