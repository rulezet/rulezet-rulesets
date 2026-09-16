rule TTP_XOR_QUAD_CurrentVersionRun_c015 {
  strings:
    $key_c015 = { 93 7a [2] b7 74 [2] 9c 58 [2] b2 7a [2] a6 61 [2] a9 7b [2] b7 66 [2] b5 67 [2] ae 61 [2] b2 66 [2] ae 49 }

  condition:
    any of them
}