rule TTP_XOR_QUAD_CurrentVersionRun_d126 {
  strings:
    $key_d126 = { 82 49 [2] a6 47 [2] 8d 6b [2] a3 49 [2] b7 52 [2] b8 48 [2] a6 55 [2] a4 54 [2] bf 52 [2] a3 55 [2] bf 7a }

  condition:
    any of them
}