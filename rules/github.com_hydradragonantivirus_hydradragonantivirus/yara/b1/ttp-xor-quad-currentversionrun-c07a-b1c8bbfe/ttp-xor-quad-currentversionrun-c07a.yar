rule TTP_XOR_QUAD_CurrentVersionRun_c07a {
  strings:
    $key_c07a = { 93 15 [2] b7 1b [2] 9c 37 [2] b2 15 [2] a6 0e [2] a9 14 [2] b7 09 [2] b5 08 [2] ae 0e [2] b2 09 [2] ae 26 }

  condition:
    any of them
}