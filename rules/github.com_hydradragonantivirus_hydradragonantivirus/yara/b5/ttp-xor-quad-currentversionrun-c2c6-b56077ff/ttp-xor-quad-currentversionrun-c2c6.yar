rule TTP_XOR_QUAD_CurrentVersionRun_c2c6 {
  strings:
    $key_c2c6 = { 91 a9 [2] b5 a7 [2] 9e 8b [2] b0 a9 [2] a4 b2 [2] ab a8 [2] b5 b5 [2] b7 b4 [2] ac b2 [2] b0 b5 [2] ac 9a }

  condition:
    any of them
}