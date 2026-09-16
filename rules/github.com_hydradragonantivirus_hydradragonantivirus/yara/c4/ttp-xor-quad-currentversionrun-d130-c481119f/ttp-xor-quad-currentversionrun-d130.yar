rule TTP_XOR_QUAD_CurrentVersionRun_d130 {
  strings:
    $key_d130 = { 82 5f [2] a6 51 [2] 8d 7d [2] a3 5f [2] b7 44 [2] b8 5e [2] a6 43 [2] a4 42 [2] bf 44 [2] a3 43 [2] bf 6c }

  condition:
    any of them
}