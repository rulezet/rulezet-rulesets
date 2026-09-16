rule TTP_XOR_QUAD_CurrentVersionRun_c704 {
  strings:
    $key_c704 = { 94 6b [2] b0 65 [2] 9b 49 [2] b5 6b [2] a1 70 [2] ae 6a [2] b0 77 [2] b2 76 [2] a9 70 [2] b5 77 [2] a9 58 }

  condition:
    any of them
}