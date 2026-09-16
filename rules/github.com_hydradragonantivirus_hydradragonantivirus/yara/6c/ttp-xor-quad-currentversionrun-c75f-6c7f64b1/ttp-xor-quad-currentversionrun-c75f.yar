rule TTP_XOR_QUAD_CurrentVersionRun_c75f {
  strings:
    $key_c75f = { 94 30 [2] b0 3e [2] 9b 12 [2] b5 30 [2] a1 2b [2] ae 31 [2] b0 2c [2] b2 2d [2] a9 2b [2] b5 2c [2] a9 03 }

  condition:
    any of them
}