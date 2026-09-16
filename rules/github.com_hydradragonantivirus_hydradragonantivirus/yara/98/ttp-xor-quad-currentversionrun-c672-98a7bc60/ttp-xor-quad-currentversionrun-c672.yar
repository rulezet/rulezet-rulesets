rule TTP_XOR_QUAD_CurrentVersionRun_c672 {
  strings:
    $key_c672 = { 95 1d [2] b1 13 [2] 9a 3f [2] b4 1d [2] a0 06 [2] af 1c [2] b1 01 [2] b3 00 [2] a8 06 [2] b4 01 [2] a8 2e }

  condition:
    any of them
}