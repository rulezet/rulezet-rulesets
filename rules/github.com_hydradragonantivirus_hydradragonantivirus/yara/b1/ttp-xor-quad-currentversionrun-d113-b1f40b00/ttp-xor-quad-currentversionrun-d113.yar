rule TTP_XOR_QUAD_CurrentVersionRun_d113 {
  strings:
    $key_d113 = { 82 7c [2] a6 72 [2] 8d 5e [2] a3 7c [2] b7 67 [2] b8 7d [2] a6 60 [2] a4 61 [2] bf 67 [2] a3 60 [2] bf 4f }

  condition:
    any of them
}