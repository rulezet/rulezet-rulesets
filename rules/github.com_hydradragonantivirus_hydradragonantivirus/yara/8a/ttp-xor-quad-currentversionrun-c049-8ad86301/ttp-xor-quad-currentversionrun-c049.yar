rule TTP_XOR_QUAD_CurrentVersionRun_c049 {
  strings:
    $key_c049 = { 93 26 [2] b7 28 [2] 9c 04 [2] b2 26 [2] a6 3d [2] a9 27 [2] b7 3a [2] b5 3b [2] ae 3d [2] b2 3a [2] ae 15 }

  condition:
    any of them
}