rule TTP_XOR_QUAD_CurrentVersionRun_c745 {
  strings:
    $key_c745 = { 94 2a [2] b0 24 [2] 9b 08 [2] b5 2a [2] a1 31 [2] ae 2b [2] b0 36 [2] b2 37 [2] a9 31 [2] b5 36 [2] a9 19 }

  condition:
    any of them
}