rule TTP_XOR_QUAD_CurrentVersionRun_c652 {
  strings:
    $key_c652 = { 95 3d [2] b1 33 [2] 9a 1f [2] b4 3d [2] a0 26 [2] af 3c [2] b1 21 [2] b3 20 [2] a8 26 [2] b4 21 [2] a8 0e }

  condition:
    any of them
}