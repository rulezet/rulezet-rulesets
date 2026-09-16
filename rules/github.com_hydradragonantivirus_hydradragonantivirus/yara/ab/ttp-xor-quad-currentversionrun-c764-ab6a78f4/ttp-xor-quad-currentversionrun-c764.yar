rule TTP_XOR_QUAD_CurrentVersionRun_c764 {
  strings:
    $key_c764 = { 94 0b [2] b0 05 [2] 9b 29 [2] b5 0b [2] a1 10 [2] ae 0a [2] b0 17 [2] b2 16 [2] a9 10 [2] b5 17 [2] a9 38 }

  condition:
    any of them
}