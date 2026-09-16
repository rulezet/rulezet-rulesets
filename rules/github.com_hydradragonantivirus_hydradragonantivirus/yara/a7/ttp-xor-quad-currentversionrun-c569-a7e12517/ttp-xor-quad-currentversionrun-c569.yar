rule TTP_XOR_QUAD_CurrentVersionRun_c569 {
  strings:
    $key_c569 = { 96 06 [2] b2 08 [2] 99 24 [2] b7 06 [2] a3 1d [2] ac 07 [2] b2 1a [2] b0 1b [2] ab 1d [2] b7 1a [2] ab 35 }

  condition:
    any of them
}