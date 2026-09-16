rule TTP_XOR_QUAD_CurrentVersionRun_c3d7 {
  strings:
    $key_c3d7 = { 90 b8 [2] b4 b6 [2] 9f 9a [2] b1 b8 [2] a5 a3 [2] aa b9 [2] b4 a4 [2] b6 a5 [2] ad a3 [2] b1 a4 [2] ad 8b }

  condition:
    any of them
}