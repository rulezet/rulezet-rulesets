rule TTP_XOR_QUAD_CurrentVersionRun_c547 {
  strings:
    $key_c547 = { 96 28 [2] b2 26 [2] 99 0a [2] b7 28 [2] a3 33 [2] ac 29 [2] b2 34 [2] b0 35 [2] ab 33 [2] b7 34 [2] ab 1b }

  condition:
    any of them
}