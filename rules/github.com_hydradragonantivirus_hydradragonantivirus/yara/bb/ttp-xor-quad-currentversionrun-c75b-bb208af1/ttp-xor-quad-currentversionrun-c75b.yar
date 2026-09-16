rule TTP_XOR_QUAD_CurrentVersionRun_c75b {
  strings:
    $key_c75b = { 94 34 [2] b0 3a [2] 9b 16 [2] b5 34 [2] a1 2f [2] ae 35 [2] b0 28 [2] b2 29 [2] a9 2f [2] b5 28 [2] a9 07 }

  condition:
    any of them
}