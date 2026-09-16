rule TTP_XOR_QUAD_CurrentVersionRun_c7e4 {
  strings:
    $key_c7e4 = { 94 8b [2] b0 85 [2] 9b a9 [2] b5 8b [2] a1 90 [2] ae 8a [2] b0 97 [2] b2 96 [2] a9 90 [2] b5 97 [2] a9 b8 }

  condition:
    any of them
}