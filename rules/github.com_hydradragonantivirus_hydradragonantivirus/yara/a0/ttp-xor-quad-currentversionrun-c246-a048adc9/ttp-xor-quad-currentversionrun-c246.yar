rule TTP_XOR_QUAD_CurrentVersionRun_c246 {
  strings:
    $key_c246 = { 91 29 [2] b5 27 [2] 9e 0b [2] b0 29 [2] a4 32 [2] ab 28 [2] b5 35 [2] b7 34 [2] ac 32 [2] b0 35 [2] ac 1a }

  condition:
    any of them
}