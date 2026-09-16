rule TTP_XOR_QUAD_CurrentVersionRun_c517 {
  strings:
    $key_c517 = { 96 78 [2] b2 76 [2] 99 5a [2] b7 78 [2] a3 63 [2] ac 79 [2] b2 64 [2] b0 65 [2] ab 63 [2] b7 64 [2] ab 4b }

  condition:
    any of them
}