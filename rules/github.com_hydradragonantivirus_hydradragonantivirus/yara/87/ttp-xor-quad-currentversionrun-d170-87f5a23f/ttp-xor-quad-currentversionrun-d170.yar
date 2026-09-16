rule TTP_XOR_QUAD_CurrentVersionRun_d170 {
  strings:
    $key_d170 = { 82 1f [2] a6 11 [2] 8d 3d [2] a3 1f [2] b7 04 [2] b8 1e [2] a6 03 [2] a4 02 [2] bf 04 [2] a3 03 [2] bf 2c }

  condition:
    any of them
}