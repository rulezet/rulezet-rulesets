rule TTP_XOR_QUAD_CurrentVersionRun_c449 {
  strings:
    $key_c449 = { 97 26 [2] b3 28 [2] 98 04 [2] b6 26 [2] a2 3d [2] ad 27 [2] b3 3a [2] b1 3b [2] aa 3d [2] b6 3a [2] aa 15 }

  condition:
    any of them
}