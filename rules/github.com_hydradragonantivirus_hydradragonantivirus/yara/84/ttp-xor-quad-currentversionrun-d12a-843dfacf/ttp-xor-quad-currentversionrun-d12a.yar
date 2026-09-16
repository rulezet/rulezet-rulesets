rule TTP_XOR_QUAD_CurrentVersionRun_d12a {
  strings:
    $key_d12a = { 82 45 [2] a6 4b [2] 8d 67 [2] a3 45 [2] b7 5e [2] b8 44 [2] a6 59 [2] a4 58 [2] bf 5e [2] a3 59 [2] bf 76 }

  condition:
    any of them
}