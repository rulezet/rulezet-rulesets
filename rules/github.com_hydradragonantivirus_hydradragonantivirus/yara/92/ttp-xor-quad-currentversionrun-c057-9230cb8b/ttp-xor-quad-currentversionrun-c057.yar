rule TTP_XOR_QUAD_CurrentVersionRun_c057 {
  strings:
    $key_c057 = { 93 38 [2] b7 36 [2] 9c 1a [2] b2 38 [2] a6 23 [2] a9 39 [2] b7 24 [2] b5 25 [2] ae 23 [2] b2 24 [2] ae 0b }

  condition:
    any of them
}