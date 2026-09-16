rule TTP_XOR_QUAD_CurrentVersionRun_d1f1 {
  strings:
    $key_d1f1 = { 82 9e [2] a6 90 [2] 8d bc [2] a3 9e [2] b7 85 [2] b8 9f [2] a6 82 [2] a4 83 [2] bf 85 [2] a3 82 [2] bf ad }

  condition:
    any of them
}