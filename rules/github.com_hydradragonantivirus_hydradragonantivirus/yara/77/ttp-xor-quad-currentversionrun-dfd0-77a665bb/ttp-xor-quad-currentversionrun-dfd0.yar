rule TTP_XOR_QUAD_CurrentVersionRun_dfd0 {
  strings:
    $key_dfd0 = { 8c bf [2] a8 b1 [2] 83 9d [2] ad bf [2] b9 a4 [2] b6 be [2] a8 a3 [2] aa a2 [2] b1 a4 [2] ad a3 [2] b1 8c }

  condition:
    any of them
}