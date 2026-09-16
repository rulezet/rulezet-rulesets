rule TTP_XOR_QUAD_CurrentVersionRun_c349 {
  strings:
    $key_c349 = { 90 26 [2] b4 28 [2] 9f 04 [2] b1 26 [2] a5 3d [2] aa 27 [2] b4 3a [2] b6 3b [2] ad 3d [2] b1 3a [2] ad 15 }

  condition:
    any of them
}