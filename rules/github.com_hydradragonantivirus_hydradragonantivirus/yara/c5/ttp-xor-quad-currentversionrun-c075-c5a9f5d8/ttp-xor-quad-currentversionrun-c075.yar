rule TTP_XOR_QUAD_CurrentVersionRun_c075 {
  strings:
    $key_c075 = { 93 1a [2] b7 14 [2] 9c 38 [2] b2 1a [2] a6 01 [2] a9 1b [2] b7 06 [2] b5 07 [2] ae 01 [2] b2 06 [2] ae 29 }

  condition:
    any of them
}