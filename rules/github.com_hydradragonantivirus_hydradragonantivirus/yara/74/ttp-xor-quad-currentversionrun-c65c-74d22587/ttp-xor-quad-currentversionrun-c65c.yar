rule TTP_XOR_QUAD_CurrentVersionRun_c65c {
  strings:
    $key_c65c = { 95 33 [2] b1 3d [2] 9a 11 [2] b4 33 [2] a0 28 [2] af 32 [2] b1 2f [2] b3 2e [2] a8 28 [2] b4 2f [2] a8 00 }

  condition:
    any of them
}