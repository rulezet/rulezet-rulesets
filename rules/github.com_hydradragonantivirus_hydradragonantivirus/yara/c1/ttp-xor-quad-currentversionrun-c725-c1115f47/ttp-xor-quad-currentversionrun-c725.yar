rule TTP_XOR_QUAD_CurrentVersionRun_c725 {
  strings:
    $key_c725 = { 94 4a [2] b0 44 [2] 9b 68 [2] b5 4a [2] a1 51 [2] ae 4b [2] b0 56 [2] b2 57 [2] a9 51 [2] b5 56 [2] a9 79 }

  condition:
    any of them
}