rule TTP_XOR_QUAD_CurrentVersionRun_c005 {
  strings:
    $key_c005 = { 93 6a [2] b7 64 [2] 9c 48 [2] b2 6a [2] a6 71 [2] a9 6b [2] b7 76 [2] b5 77 [2] ae 71 [2] b2 76 [2] ae 59 }

  condition:
    any of them
}