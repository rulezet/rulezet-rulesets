rule TTP_XOR_QUAD_CurrentVersionRun_d100 {
  strings:
    $key_d100 = { 82 6f [2] a6 61 [2] 8d 4d [2] a3 6f [2] b7 74 [2] b8 6e [2] a6 73 [2] a4 72 [2] bf 74 [2] a3 73 [2] bf 5c }

  condition:
    any of them
}