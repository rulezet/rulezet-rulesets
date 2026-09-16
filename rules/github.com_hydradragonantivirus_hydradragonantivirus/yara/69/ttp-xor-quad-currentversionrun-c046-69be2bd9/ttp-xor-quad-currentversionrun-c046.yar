rule TTP_XOR_QUAD_CurrentVersionRun_c046 {
  strings:
    $key_c046 = { 93 29 [2] b7 27 [2] 9c 0b [2] b2 29 [2] a6 32 [2] a9 28 [2] b7 35 [2] b5 34 [2] ae 32 [2] b2 35 [2] ae 1a }

  condition:
    any of them
}