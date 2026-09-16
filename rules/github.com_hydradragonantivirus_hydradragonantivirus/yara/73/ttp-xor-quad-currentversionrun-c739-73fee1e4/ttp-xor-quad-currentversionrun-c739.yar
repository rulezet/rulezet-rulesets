rule TTP_XOR_QUAD_CurrentVersionRun_c739 {
  strings:
    $key_c739 = { 94 56 [2] b0 58 [2] 9b 74 [2] b5 56 [2] a1 4d [2] ae 57 [2] b0 4a [2] b2 4b [2] a9 4d [2] b5 4a [2] a9 65 }

  condition:
    any of them
}