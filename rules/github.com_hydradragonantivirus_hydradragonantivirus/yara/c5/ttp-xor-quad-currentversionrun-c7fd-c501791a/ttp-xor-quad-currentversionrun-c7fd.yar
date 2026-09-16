rule TTP_XOR_QUAD_CurrentVersionRun_c7fd {
  strings:
    $key_c7fd = { 94 92 [2] b0 9c [2] 9b b0 [2] b5 92 [2] a1 89 [2] ae 93 [2] b0 8e [2] b2 8f [2] a9 89 [2] b5 8e [2] a9 a1 }

  condition:
    any of them
}