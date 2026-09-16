rule TTP_XOR_QUAD_CurrentVersionRun_c078 {
  strings:
    $key_c078 = { 93 17 [2] b7 19 [2] 9c 35 [2] b2 17 [2] a6 0c [2] a9 16 [2] b7 0b [2] b5 0a [2] ae 0c [2] b2 0b [2] ae 24 }

  condition:
    any of them
}