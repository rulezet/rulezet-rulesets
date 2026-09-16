rule TTP_XOR_QUAD_CurrentVersionRun_c07c {
  strings:
    $key_c07c = { 93 13 [2] b7 1d [2] 9c 31 [2] b2 13 [2] a6 08 [2] a9 12 [2] b7 0f [2] b5 0e [2] ae 08 [2] b2 0f [2] ae 20 }

  condition:
    any of them
}