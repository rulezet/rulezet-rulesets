rule TTP_XOR_QUAD_CurrentVersionRun_d11a {
  strings:
    $key_d11a = { 82 75 [2] a6 7b [2] 8d 57 [2] a3 75 [2] b7 6e [2] b8 74 [2] a6 69 [2] a4 68 [2] bf 6e [2] a3 69 [2] bf 46 }

  condition:
    any of them
}