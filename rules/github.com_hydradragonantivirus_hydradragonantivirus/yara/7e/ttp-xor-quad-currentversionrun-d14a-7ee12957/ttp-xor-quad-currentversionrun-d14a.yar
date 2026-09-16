rule TTP_XOR_QUAD_CurrentVersionRun_d14a {
  strings:
    $key_d14a = { 82 25 [2] a6 2b [2] 8d 07 [2] a3 25 [2] b7 3e [2] b8 24 [2] a6 39 [2] a4 38 [2] bf 3e [2] a3 39 [2] bf 16 }

  condition:
    any of them
}