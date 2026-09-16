rule TTP_XOR_QUAD_CurrentVersionRun_c058 {
  strings:
    $key_c058 = { 93 37 [2] b7 39 [2] 9c 15 [2] b2 37 [2] a6 2c [2] a9 36 [2] b7 2b [2] b5 2a [2] ae 2c [2] b2 2b [2] ae 04 }

  condition:
    any of them
}