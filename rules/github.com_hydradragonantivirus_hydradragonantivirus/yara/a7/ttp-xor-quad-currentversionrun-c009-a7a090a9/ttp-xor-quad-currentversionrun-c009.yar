rule TTP_XOR_QUAD_CurrentVersionRun_c009 {
  strings:
    $key_c009 = { 93 66 [2] b7 68 [2] 9c 44 [2] b2 66 [2] a6 7d [2] a9 67 [2] b7 7a [2] b5 7b [2] ae 7d [2] b2 7a [2] ae 55 }

  condition:
    any of them
}