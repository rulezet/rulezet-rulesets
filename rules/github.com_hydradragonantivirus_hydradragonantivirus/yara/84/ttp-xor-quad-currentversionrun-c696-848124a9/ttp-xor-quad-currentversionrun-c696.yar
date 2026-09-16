rule TTP_XOR_QUAD_CurrentVersionRun_c696 {
  strings:
    $key_c696 = { 95 f9 [2] b1 f7 [2] 9a db [2] b4 f9 [2] a0 e2 [2] af f8 [2] b1 e5 [2] b3 e4 [2] a8 e2 [2] b4 e5 [2] a8 ca }

  condition:
    any of them
}