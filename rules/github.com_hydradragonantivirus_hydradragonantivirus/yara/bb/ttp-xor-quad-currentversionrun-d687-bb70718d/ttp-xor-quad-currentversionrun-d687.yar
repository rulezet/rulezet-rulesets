rule TTP_XOR_QUAD_CurrentVersionRun_d687 {
  strings:
    $key_d687 = { 85 e8 [2] a1 e6 [2] 8a ca [2] a4 e8 [2] b0 f3 [2] bf e9 [2] a1 f4 [2] a3 f5 [2] b8 f3 [2] a4 f4 [2] b8 db }

  condition:
    any of them
}