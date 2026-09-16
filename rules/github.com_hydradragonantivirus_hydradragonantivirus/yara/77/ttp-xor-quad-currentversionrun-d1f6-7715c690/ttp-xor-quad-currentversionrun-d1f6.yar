rule TTP_XOR_QUAD_CurrentVersionRun_d1f6 {
  strings:
    $key_d1f6 = { 82 99 [2] a6 97 [2] 8d bb [2] a3 99 [2] b7 82 [2] b8 98 [2] a6 85 [2] a4 84 [2] bf 82 [2] a3 85 [2] bf aa }

  condition:
    any of them
}