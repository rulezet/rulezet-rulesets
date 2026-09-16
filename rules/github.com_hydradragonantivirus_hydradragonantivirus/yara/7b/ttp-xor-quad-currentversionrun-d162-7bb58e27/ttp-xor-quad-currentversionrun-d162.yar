rule TTP_XOR_QUAD_CurrentVersionRun_d162 {
  strings:
    $key_d162 = { 82 0d [2] a6 03 [2] 8d 2f [2] a3 0d [2] b7 16 [2] b8 0c [2] a6 11 [2] a4 10 [2] bf 16 [2] a3 11 [2] bf 3e }

  condition:
    any of them
}