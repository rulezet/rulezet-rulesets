rule TTP_XOR_QUAD_CurrentVersionRun_c067 {
  strings:
    $key_c067 = { 93 08 [2] b7 06 [2] 9c 2a [2] b2 08 [2] a6 13 [2] a9 09 [2] b7 14 [2] b5 15 [2] ae 13 [2] b2 14 [2] ae 3b }

  condition:
    any of them
}