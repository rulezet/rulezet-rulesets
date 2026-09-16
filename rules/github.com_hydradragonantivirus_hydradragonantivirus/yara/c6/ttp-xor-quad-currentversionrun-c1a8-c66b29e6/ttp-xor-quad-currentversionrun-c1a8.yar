rule TTP_XOR_QUAD_CurrentVersionRun_c1a8 {
  strings:
    $key_c1a8 = { 92 c7 [2] b6 c9 [2] 9d e5 [2] b3 c7 [2] a7 dc [2] a8 c6 [2] b6 db [2] b4 da [2] af dc [2] b3 db [2] af f4 }

  condition:
    any of them
}