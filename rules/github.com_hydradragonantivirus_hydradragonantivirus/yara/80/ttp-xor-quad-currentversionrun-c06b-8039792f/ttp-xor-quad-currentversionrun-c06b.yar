rule TTP_XOR_QUAD_CurrentVersionRun_c06b {
  strings:
    $key_c06b = { 93 04 [2] b7 0a [2] 9c 26 [2] b2 04 [2] a6 1f [2] a9 05 [2] b7 18 [2] b5 19 [2] ae 1f [2] b2 18 [2] ae 37 }

  condition:
    any of them
}