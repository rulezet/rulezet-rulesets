rule TTP_XOR_QUAD_CurrentVersionRun_d15c {
  strings:
    $key_d15c = { 82 33 [2] a6 3d [2] 8d 11 [2] a3 33 [2] b7 28 [2] b8 32 [2] a6 2f [2] a4 2e [2] bf 28 [2] a3 2f [2] bf 00 }

  condition:
    any of them
}