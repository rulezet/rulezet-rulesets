rule TTP_XOR_QUAD_CurrentVersionRun_c687 {
  strings:
    $key_c687 = { 95 e8 [2] b1 e6 [2] 9a ca [2] b4 e8 [2] a0 f3 [2] af e9 [2] b1 f4 [2] b3 f5 [2] a8 f3 [2] b4 f4 [2] a8 db }

  condition:
    any of them
}