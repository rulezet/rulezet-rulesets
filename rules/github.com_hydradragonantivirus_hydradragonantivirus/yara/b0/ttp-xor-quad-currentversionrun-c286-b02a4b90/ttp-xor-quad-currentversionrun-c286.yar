rule TTP_XOR_QUAD_CurrentVersionRun_c286 {
  strings:
    $key_c286 = { 91 e9 [2] b5 e7 [2] 9e cb [2] b0 e9 [2] a4 f2 [2] ab e8 [2] b5 f5 [2] b7 f4 [2] ac f2 [2] b0 f5 [2] ac da }

  condition:
    any of them
}