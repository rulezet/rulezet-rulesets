rule TTP_XOR_QUAD_CurrentVersionRun_c259 {
  strings:
    $key_c259 = { 91 36 [2] b5 38 [2] 9e 14 [2] b0 36 [2] a4 2d [2] ab 37 [2] b5 2a [2] b7 2b [2] ac 2d [2] b0 2a [2] ac 05 }

  condition:
    any of them
}