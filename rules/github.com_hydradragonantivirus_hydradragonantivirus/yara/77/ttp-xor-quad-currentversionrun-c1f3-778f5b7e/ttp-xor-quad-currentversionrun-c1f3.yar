rule TTP_XOR_QUAD_CurrentVersionRun_c1f3 {
  strings:
    $key_c1f3 = { 92 9c [2] b6 92 [2] 9d be [2] b3 9c [2] a7 87 [2] a8 9d [2] b6 80 [2] b4 81 [2] af 87 [2] b3 80 [2] af af }

  condition:
    any of them
}