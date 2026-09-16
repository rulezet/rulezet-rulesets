rule TTP_XOR_QUAD_CurrentVersionRun_c3d1 {
  strings:
    $key_c3d1 = { 90 be [2] b4 b0 [2] 9f 9c [2] b1 be [2] a5 a5 [2] aa bf [2] b4 a2 [2] b6 a3 [2] ad a5 [2] b1 a2 [2] ad 8d }

  condition:
    any of them
}