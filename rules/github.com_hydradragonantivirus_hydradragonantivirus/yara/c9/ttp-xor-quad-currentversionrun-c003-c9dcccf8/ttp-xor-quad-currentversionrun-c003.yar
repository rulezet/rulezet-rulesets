rule TTP_XOR_QUAD_CurrentVersionRun_c003 {
  strings:
    $key_c003 = { 93 6c [2] b7 62 [2] 9c 4e [2] b2 6c [2] a6 77 [2] a9 6d [2] b7 70 [2] b5 71 [2] ae 77 [2] b2 70 [2] ae 5f }

  condition:
    any of them
}