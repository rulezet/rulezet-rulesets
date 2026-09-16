rule TTP_XOR_QUAD_CurrentVersionRun_c7e9 {
  strings:
    $key_c7e9 = { 94 86 [2] b0 88 [2] 9b a4 [2] b5 86 [2] a1 9d [2] ae 87 [2] b0 9a [2] b2 9b [2] a9 9d [2] b5 9a [2] a9 b5 }

  condition:
    any of them
}