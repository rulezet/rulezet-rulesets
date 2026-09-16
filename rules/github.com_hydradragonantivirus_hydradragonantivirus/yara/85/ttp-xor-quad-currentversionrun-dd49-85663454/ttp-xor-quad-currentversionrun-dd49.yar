rule TTP_XOR_QUAD_CurrentVersionRun_dd49 {
  strings:
    $key_dd49 = { 8e 26 [2] aa 28 [2] 81 04 [2] af 26 [2] bb 3d [2] b4 27 [2] aa 3a [2] a8 3b [2] b3 3d [2] af 3a [2] b3 15 }

  condition:
    any of them
}