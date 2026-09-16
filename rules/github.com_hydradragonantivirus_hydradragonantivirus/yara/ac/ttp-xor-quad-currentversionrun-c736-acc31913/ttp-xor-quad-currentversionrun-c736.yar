rule TTP_XOR_QUAD_CurrentVersionRun_c736 {
  strings:
    $key_c736 = { 94 59 [2] b0 57 [2] 9b 7b [2] b5 59 [2] a1 42 [2] ae 58 [2] b0 45 [2] b2 44 [2] a9 42 [2] b5 45 [2] a9 6a }

  condition:
    any of them
}