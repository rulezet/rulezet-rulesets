rule TTP_XOR_QUAD_CurrentVersionRun_c039 {
  strings:
    $key_c039 = { 93 56 [2] b7 58 [2] 9c 74 [2] b2 56 [2] a6 4d [2] a9 57 [2] b7 4a [2] b5 4b [2] ae 4d [2] b2 4a [2] ae 65 }

  condition:
    any of them
}