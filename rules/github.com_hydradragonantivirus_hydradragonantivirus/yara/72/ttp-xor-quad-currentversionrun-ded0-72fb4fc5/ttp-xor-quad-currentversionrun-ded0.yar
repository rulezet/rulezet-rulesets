rule TTP_XOR_QUAD_CurrentVersionRun_ded0 {
  strings:
    $key_ded0 = { 8d bf [2] a9 b1 [2] 82 9d [2] ac bf [2] b8 a4 [2] b7 be [2] a9 a3 [2] ab a2 [2] b0 a4 [2] ac a3 [2] b0 8c }

  condition:
    any of them
}