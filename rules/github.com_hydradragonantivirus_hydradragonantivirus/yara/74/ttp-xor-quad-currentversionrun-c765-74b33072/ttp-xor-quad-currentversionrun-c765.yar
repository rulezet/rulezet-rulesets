rule TTP_XOR_QUAD_CurrentVersionRun_c765 {
  strings:
    $key_c765 = { 94 0a [2] b0 04 [2] 9b 28 [2] b5 0a [2] a1 11 [2] ae 0b [2] b0 16 [2] b2 17 [2] a9 11 [2] b5 16 [2] a9 39 }

  condition:
    any of them
}