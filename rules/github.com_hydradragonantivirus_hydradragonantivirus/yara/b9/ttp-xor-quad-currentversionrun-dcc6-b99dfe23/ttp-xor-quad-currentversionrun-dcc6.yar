rule TTP_XOR_QUAD_CurrentVersionRun_dcc6 {
  strings:
    $key_dcc6 = { 8f a9 [2] ab a7 [2] 80 8b [2] ae a9 [2] ba b2 [2] b5 a8 [2] ab b5 [2] a9 b4 [2] b2 b2 [2] ae b5 [2] b2 9a }

  condition:
    any of them
}