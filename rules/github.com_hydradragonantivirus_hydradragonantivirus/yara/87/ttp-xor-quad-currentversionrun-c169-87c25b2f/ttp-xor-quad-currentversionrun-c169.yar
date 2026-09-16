rule TTP_XOR_QUAD_CurrentVersionRun_c169 {
  strings:
    $key_c169 = { 92 06 [2] b6 08 [2] 9d 24 [2] b3 06 [2] a7 1d [2] a8 07 [2] b6 1a [2] b4 1b [2] af 1d [2] b3 1a [2] af 35 }

  condition:
    any of them
}