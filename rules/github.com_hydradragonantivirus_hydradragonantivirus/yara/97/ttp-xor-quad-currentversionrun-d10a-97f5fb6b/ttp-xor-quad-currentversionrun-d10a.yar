rule TTP_XOR_QUAD_CurrentVersionRun_d10a {
  strings:
    $key_d10a = { 82 65 [2] a6 6b [2] 8d 47 [2] a3 65 [2] b7 7e [2] b8 64 [2] a6 79 [2] a4 78 [2] bf 7e [2] a3 79 [2] bf 56 }

  condition:
    any of them
}