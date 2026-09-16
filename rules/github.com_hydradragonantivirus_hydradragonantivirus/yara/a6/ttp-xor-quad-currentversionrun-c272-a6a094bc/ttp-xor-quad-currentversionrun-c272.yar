rule TTP_XOR_QUAD_CurrentVersionRun_c272 {
  strings:
    $key_c272 = { 91 1d [2] b5 13 [2] 9e 3f [2] b0 1d [2] a4 06 [2] ab 1c [2] b5 01 [2] b7 00 [2] ac 06 [2] b0 01 [2] ac 2e }

  condition:
    any of them
}