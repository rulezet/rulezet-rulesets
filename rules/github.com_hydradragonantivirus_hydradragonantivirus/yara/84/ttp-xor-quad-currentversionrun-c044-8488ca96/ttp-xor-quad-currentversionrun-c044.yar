rule TTP_XOR_QUAD_CurrentVersionRun_c044 {
  strings:
    $key_c044 = { 93 2b [2] b7 25 [2] 9c 09 [2] b2 2b [2] a6 30 [2] a9 2a [2] b7 37 [2] b5 36 [2] ae 30 [2] b2 37 [2] ae 18 }

  condition:
    any of them
}