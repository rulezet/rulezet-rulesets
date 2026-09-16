rule TTP_XOR_QUAD_CurrentVersionRun_d16a {
  strings:
    $key_d16a = { 82 05 [2] a6 0b [2] 8d 27 [2] a3 05 [2] b7 1e [2] b8 04 [2] a6 19 [2] a4 18 [2] bf 1e [2] a3 19 [2] bf 36 }

  condition:
    any of them
}