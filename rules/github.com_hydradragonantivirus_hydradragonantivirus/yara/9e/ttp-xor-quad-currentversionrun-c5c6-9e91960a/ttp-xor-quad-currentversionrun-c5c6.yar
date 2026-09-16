rule TTP_XOR_QUAD_CurrentVersionRun_c5c6 {
  strings:
    $key_c5c6 = { 96 a9 [2] b2 a7 [2] 99 8b [2] b7 a9 [2] a3 b2 [2] ac a8 [2] b2 b5 [2] b0 b4 [2] ab b2 [2] b7 b5 [2] ab 9a }

  condition:
    any of them
}