rule TTP_XOR_QUAD_CurrentVersionRun_d17c {
  strings:
    $key_d17c = { 82 13 [2] a6 1d [2] 8d 31 [2] a3 13 [2] b7 08 [2] b8 12 [2] a6 0f [2] a4 0e [2] bf 08 [2] a3 0f [2] bf 20 }

  condition:
    any of them
}