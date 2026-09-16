rule TTP_XOR_QUAD_CurrentVersionRun_c64e {
  strings:
    $key_c64e = { 95 21 [2] b1 2f [2] 9a 03 [2] b4 21 [2] a0 3a [2] af 20 [2] b1 3d [2] b3 3c [2] a8 3a [2] b4 3d [2] a8 12 }

  condition:
    any of them
}