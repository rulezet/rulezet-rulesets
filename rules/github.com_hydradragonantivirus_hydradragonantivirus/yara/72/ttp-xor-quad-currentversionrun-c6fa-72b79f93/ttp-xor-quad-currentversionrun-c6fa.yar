rule TTP_XOR_QUAD_CurrentVersionRun_c6fa {
  strings:
    $key_c6fa = { 95 95 [2] b1 9b [2] 9a b7 [2] b4 95 [2] a0 8e [2] af 94 [2] b1 89 [2] b3 88 [2] a8 8e [2] b4 89 [2] a8 a6 }

  condition:
    any of them
}