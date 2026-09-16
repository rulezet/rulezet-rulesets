rule TTP_XOR_QUAD_CurrentVersionRun_c247 {
  strings:
    $key_c247 = { 91 28 [2] b5 26 [2] 9e 0a [2] b0 28 [2] a4 33 [2] ab 29 [2] b5 34 [2] b7 35 [2] ac 33 [2] b0 34 [2] ac 1b }

  condition:
    any of them
}