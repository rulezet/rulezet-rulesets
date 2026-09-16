rule TTP_XOR_QUAD_CurrentVersionRun_c3d6 {
  strings:
    $key_c3d6 = { 90 b9 [2] b4 b7 [2] 9f 9b [2] b1 b9 [2] a5 a2 [2] aa b8 [2] b4 a5 [2] b6 a4 [2] ad a2 [2] b1 a5 [2] ad 8a }

  condition:
    any of them
}