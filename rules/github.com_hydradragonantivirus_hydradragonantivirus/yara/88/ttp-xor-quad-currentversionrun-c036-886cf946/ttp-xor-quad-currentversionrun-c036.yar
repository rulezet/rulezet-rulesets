rule TTP_XOR_QUAD_CurrentVersionRun_c036 {
  strings:
    $key_c036 = { 93 59 [2] b7 57 [2] 9c 7b [2] b2 59 [2] a6 42 [2] a9 58 [2] b7 45 [2] b5 44 [2] ae 42 [2] b2 45 [2] ae 6a }

  condition:
    any of them
}