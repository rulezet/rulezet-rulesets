rule TTP_XOR_QUAD_CurrentVersionRun_d122 {
  strings:
    $key_d122 = { 82 4d [2] a6 43 [2] 8d 6f [2] a3 4d [2] b7 56 [2] b8 4c [2] a6 51 [2] a4 50 [2] bf 56 [2] a3 51 [2] bf 7e }

  condition:
    any of them
}