rule TTP_XOR_QUAD_CurrentVersionRun_c64c {
  strings:
    $key_c64c = { 95 23 [2] b1 2d [2] 9a 01 [2] b4 23 [2] a0 38 [2] af 22 [2] b1 3f [2] b3 3e [2] a8 38 [2] b4 3f [2] a8 10 }

  condition:
    any of them
}