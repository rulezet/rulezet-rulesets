rule TTP_XOR_QUAD_CurrentVersionRun_c0e9 {
  strings:
    $key_c0e9 = { 93 86 [2] b7 88 [2] 9c a4 [2] b2 86 [2] a6 9d [2] a9 87 [2] b7 9a [2] b5 9b [2] ae 9d [2] b2 9a [2] ae b5 }

  condition:
    any of them
}