rule TTP_XOR_QUAD_CurrentVersionRun_d116 {
  strings:
    $key_d116 = { 82 79 [2] a6 77 [2] 8d 5b [2] a3 79 [2] b7 62 [2] b8 78 [2] a6 65 [2] a4 64 [2] bf 62 [2] a3 65 [2] bf 4a }

  condition:
    any of them
}