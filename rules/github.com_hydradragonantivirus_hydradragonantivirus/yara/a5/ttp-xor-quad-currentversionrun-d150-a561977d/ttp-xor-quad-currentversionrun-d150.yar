rule TTP_XOR_QUAD_CurrentVersionRun_d150 {
  strings:
    $key_d150 = { 82 3f [2] a6 31 [2] 8d 1d [2] a3 3f [2] b7 24 [2] b8 3e [2] a6 23 [2] a4 22 [2] bf 24 [2] a3 23 [2] bf 0c }

  condition:
    any of them
}