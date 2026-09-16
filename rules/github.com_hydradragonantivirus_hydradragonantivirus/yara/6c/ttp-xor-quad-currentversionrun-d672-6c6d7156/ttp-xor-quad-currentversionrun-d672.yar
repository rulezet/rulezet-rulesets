rule TTP_XOR_QUAD_CurrentVersionRun_d672 {
  strings:
    $key_d672 = { 85 1d [2] a1 13 [2] 8a 3f [2] a4 1d [2] b0 06 [2] bf 1c [2] a1 01 [2] a3 00 [2] b8 06 [2] a4 01 [2] b8 2e }

  condition:
    any of them
}