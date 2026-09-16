rule TTP_XOR_QUAD_CurrentVersionRun_c573 {
  strings:
    $key_c573 = { 96 1c [2] b2 12 [2] 99 3e [2] b7 1c [2] a3 07 [2] ac 1d [2] b2 00 [2] b0 01 [2] ab 07 [2] b7 00 [2] ab 2f }

  condition:
    any of them
}