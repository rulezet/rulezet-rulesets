rule TTP_XOR_QUAD_CurrentVersionRun_c559 {
  strings:
    $key_c559 = { 96 36 [2] b2 38 [2] 99 14 [2] b7 36 [2] a3 2d [2] ac 37 [2] b2 2a [2] b0 2b [2] ab 2d [2] b7 2a [2] ab 05 }

  condition:
    any of them
}