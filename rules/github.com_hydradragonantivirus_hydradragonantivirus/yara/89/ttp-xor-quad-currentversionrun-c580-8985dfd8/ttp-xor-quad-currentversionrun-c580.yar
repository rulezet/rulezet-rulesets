rule TTP_XOR_QUAD_CurrentVersionRun_c580 {
  strings:
    $key_c580 = { 96 ef [2] b2 e1 [2] 99 cd [2] b7 ef [2] a3 f4 [2] ac ee [2] b2 f3 [2] b0 f2 [2] ab f4 [2] b7 f3 [2] ab dc }

  condition:
    any of them
}