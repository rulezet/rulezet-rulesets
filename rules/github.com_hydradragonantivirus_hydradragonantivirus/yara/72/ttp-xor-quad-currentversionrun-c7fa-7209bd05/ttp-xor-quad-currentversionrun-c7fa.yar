rule TTP_XOR_QUAD_CurrentVersionRun_c7fa {
  strings:
    $key_c7fa = { 94 95 [2] b0 9b [2] 9b b7 [2] b5 95 [2] a1 8e [2] ae 94 [2] b0 89 [2] b2 88 [2] a9 8e [2] b5 89 [2] a9 a6 }

  condition:
    any of them
}