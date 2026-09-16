rule TTP_XOR_QUAD_CurrentVersionRun_c018 {
  strings:
    $key_c018 = { 93 77 [2] b7 79 [2] 9c 55 [2] b2 77 [2] a6 6c [2] a9 76 [2] b7 6b [2] b5 6a [2] ae 6c [2] b2 6b [2] ae 44 }

  condition:
    any of them
}