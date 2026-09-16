rule TTP_XOR_QUAD_CurrentVersionRun_c1fa {
  strings:
    $key_c1fa = { 92 95 [2] b6 9b [2] 9d b7 [2] b3 95 [2] a7 8e [2] a8 94 [2] b6 89 [2] b4 88 [2] af 8e [2] b3 89 [2] af a6 }

  condition:
    any of them
}