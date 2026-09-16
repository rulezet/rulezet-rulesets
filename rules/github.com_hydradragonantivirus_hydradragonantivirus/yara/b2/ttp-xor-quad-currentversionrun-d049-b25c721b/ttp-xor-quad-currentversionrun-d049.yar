rule TTP_XOR_QUAD_CurrentVersionRun_d049 {
  strings:
    $key_d049 = { 83 26 [2] a7 28 [2] 8c 04 [2] a2 26 [2] b6 3d [2] b9 27 [2] a7 3a [2] a5 3b [2] be 3d [2] a2 3a [2] be 15 }

  condition:
    any of them
}