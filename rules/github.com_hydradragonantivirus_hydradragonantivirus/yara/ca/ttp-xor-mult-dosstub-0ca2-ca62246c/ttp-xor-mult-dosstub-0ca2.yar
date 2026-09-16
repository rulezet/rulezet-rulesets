rule TTP_XOR_MULT_DOSStub_0ca2 {
  strings:
    $key_0ca2 = { 58 ca [2] 2c d2 [2] 6b d0 [2] 2c c1 [2] 62 cd [2] 6e c7 [2] 79 cc [2] 62 82 [2] 5f }

  condition:
    any of them
}