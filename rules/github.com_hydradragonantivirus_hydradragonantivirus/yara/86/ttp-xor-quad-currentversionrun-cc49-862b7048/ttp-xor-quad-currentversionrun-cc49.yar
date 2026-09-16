rule TTP_XOR_QUAD_CurrentVersionRun_cc49 {
  strings:
    $key_cc49 = { 9f 26 [2] bb 28 [2] 90 04 [2] be 26 [2] aa 3d [2] a5 27 [2] bb 3a [2] b9 3b [2] a2 3d [2] be 3a [2] a2 15 }

  condition:
    any of them
}