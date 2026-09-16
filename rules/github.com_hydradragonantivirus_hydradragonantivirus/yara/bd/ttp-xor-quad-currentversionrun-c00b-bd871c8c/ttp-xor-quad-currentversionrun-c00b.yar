rule TTP_XOR_QUAD_CurrentVersionRun_c00b {
  strings:
    $key_c00b = { 93 64 [2] b7 6a [2] 9c 46 [2] b2 64 [2] a6 7f [2] a9 65 [2] b7 78 [2] b5 79 [2] ae 7f [2] b2 78 [2] ae 57 }

  condition:
    any of them
}