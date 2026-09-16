rule TTP_XOR_QUAD_CurrentVersionRun_c15c {
  strings:
    $key_c15c = { 92 33 [2] b6 3d [2] 9d 11 [2] b3 33 [2] a7 28 [2] a8 32 [2] b6 2f [2] b4 2e [2] af 28 [2] b3 2f [2] af 00 }

  condition:
    any of them
}