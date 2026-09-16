rule TTP_XOR_QUAD_CurrentVersionRun_c004 {
  strings:
    $key_c004 = { 93 6b [2] b7 65 [2] 9c 49 [2] b2 6b [2] a6 70 [2] a9 6a [2] b7 77 [2] b5 76 [2] ae 70 [2] b2 77 [2] ae 58 }

  condition:
    any of them
}