rule TTP_XOR_QUAD_CurrentVersionRun_c007 {
  strings:
    $key_c007 = { 93 68 [2] b7 66 [2] 9c 4a [2] b2 68 [2] a6 73 [2] a9 69 [2] b7 74 [2] b5 75 [2] ae 73 [2] b2 74 [2] ae 5b }

  condition:
    any of them
}