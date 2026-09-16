rule TTP_XOR_QUAD_CurrentVersionRun_c714 {
  strings:
    $key_c714 = { 94 7b [2] b0 75 [2] 9b 59 [2] b5 7b [2] a1 60 [2] ae 7a [2] b0 67 [2] b2 66 [2] a9 60 [2] b5 67 [2] a9 48 }

  condition:
    any of them
}