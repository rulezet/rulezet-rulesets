rule TTP_XOR_QUAD_CurrentVersionRun_c077 {
  strings:
    $key_c077 = { 93 18 [2] b7 16 [2] 9c 3a [2] b2 18 [2] a6 03 [2] a9 19 [2] b7 04 [2] b5 05 [2] ae 03 [2] b2 04 [2] ae 2b }

  condition:
    any of them
}