rule TTP_XOR_QUAD_CurrentVersionRun_db80 {
  strings:
    $key_db80 = { 88 ef [2] ac e1 [2] 87 cd [2] a9 ef [2] bd f4 [2] b2 ee [2] ac f3 [2] ae f2 [2] b5 f4 [2] a9 f3 [2] b5 dc }

  condition:
    any of them
}