rule TTP_XOR_QUAD_CurrentVersionRun_c172 {
  strings:
    $key_c172 = { 92 1d [2] b6 13 [2] 9d 3f [2] b3 1d [2] a7 06 [2] a8 1c [2] b6 01 [2] b4 00 [2] af 06 [2] b3 01 [2] af 2e }

  condition:
    any of them
}