rule TTP_XOR_QUAD_CurrentVersionRun_d172 {
  strings:
    $key_d172 = { 82 1d [2] a6 13 [2] 8d 3f [2] a3 1d [2] b7 06 [2] b8 1c [2] a6 01 [2] a4 00 [2] bf 06 [2] a3 01 [2] bf 2e }

  condition:
    any of them
}