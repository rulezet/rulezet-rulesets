rule TTP_XOR_QUAD_CurrentVersionRun_c556 {
  strings:
    $key_c556 = { 96 39 [2] b2 37 [2] 99 1b [2] b7 39 [2] a3 22 [2] ac 38 [2] b2 25 [2] b0 24 [2] ab 22 [2] b7 25 [2] ab 0a }

  condition:
    any of them
}