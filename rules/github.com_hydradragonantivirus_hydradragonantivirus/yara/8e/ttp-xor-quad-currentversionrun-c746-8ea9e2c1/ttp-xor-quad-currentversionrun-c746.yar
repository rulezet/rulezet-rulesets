rule TTP_XOR_QUAD_CurrentVersionRun_c746 {
  strings:
    $key_c746 = { 94 29 [2] b0 27 [2] 9b 0b [2] b5 29 [2] a1 32 [2] ae 28 [2] b0 35 [2] b2 34 [2] a9 32 [2] b5 35 [2] a9 1a }

  condition:
    any of them
}