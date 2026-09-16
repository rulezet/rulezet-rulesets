rule TTP_XOR_QUAD_CurrentVersionRun_d120 {
  strings:
    $key_d120 = { 82 4f [2] a6 41 [2] 8d 6d [2] a3 4f [2] b7 54 [2] b8 4e [2] a6 53 [2] a4 52 [2] bf 54 [2] a3 53 [2] bf 7c }

  condition:
    any of them
}