rule TTP_XOR_QUAD_CurrentVersionRun_c64d {
  strings:
    $key_c64d = { 95 22 [2] b1 2c [2] 9a 00 [2] b4 22 [2] a0 39 [2] af 23 [2] b1 3e [2] b3 3f [2] a8 39 [2] b4 3e [2] a8 11 }

  condition:
    any of them
}