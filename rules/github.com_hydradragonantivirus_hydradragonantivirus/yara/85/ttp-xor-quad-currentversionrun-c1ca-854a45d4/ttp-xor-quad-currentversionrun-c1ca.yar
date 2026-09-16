rule TTP_XOR_QUAD_CurrentVersionRun_c1ca {
  strings:
    $key_c1ca = { 92 a5 [2] b6 ab [2] 9d 87 [2] b3 a5 [2] a7 be [2] a8 a4 [2] b6 b9 [2] b4 b8 [2] af be [2] b3 b9 [2] af 96 }

  condition:
    any of them
}