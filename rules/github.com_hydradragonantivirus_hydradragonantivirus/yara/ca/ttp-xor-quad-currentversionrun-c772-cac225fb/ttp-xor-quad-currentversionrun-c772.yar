rule TTP_XOR_QUAD_CurrentVersionRun_c772 {
  strings:
    $key_c772 = { 94 1d [2] b0 13 [2] 9b 3f [2] b5 1d [2] a1 06 [2] ae 1c [2] b0 01 [2] b2 00 [2] a9 06 [2] b5 01 [2] a9 2e }

  condition:
    any of them
}