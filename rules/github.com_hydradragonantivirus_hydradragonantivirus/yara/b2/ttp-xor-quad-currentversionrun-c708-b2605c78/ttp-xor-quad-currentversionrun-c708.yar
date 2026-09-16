rule TTP_XOR_QUAD_CurrentVersionRun_c708 {
  strings:
    $key_c708 = { 94 67 [2] b0 69 [2] 9b 45 [2] b5 67 [2] a1 7c [2] ae 66 [2] b0 7b [2] b2 7a [2] a9 7c [2] b5 7b [2] a9 54 }

  condition:
    any of them
}