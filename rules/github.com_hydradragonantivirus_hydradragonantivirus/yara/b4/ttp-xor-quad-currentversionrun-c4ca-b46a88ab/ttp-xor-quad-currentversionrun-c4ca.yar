rule TTP_XOR_QUAD_CurrentVersionRun_c4ca {
  strings:
    $key_c4ca = { 97 a5 [2] b3 ab [2] 98 87 [2] b6 a5 [2] a2 be [2] ad a4 [2] b3 b9 [2] b1 b8 [2] aa be [2] b6 b9 [2] aa 96 }

  condition:
    any of them
}