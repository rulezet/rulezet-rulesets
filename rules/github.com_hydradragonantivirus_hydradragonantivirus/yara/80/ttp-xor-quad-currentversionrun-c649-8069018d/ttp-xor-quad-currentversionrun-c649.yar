rule TTP_XOR_QUAD_CurrentVersionRun_c649 {
  strings:
    $key_c649 = { 95 26 [2] b1 28 [2] 9a 04 [2] b4 26 [2] a0 3d [2] af 27 [2] b1 3a [2] b3 3b [2] a8 3d [2] b4 3a [2] a8 15 }

  condition:
    any of them
}