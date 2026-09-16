rule TTP_XOR_MULT_DOSStub_4fa5 {
  strings:
    $key_4fa5 = { 1b cd [2] 6f d5 [2] 28 d7 [2] 6f c6 [2] 21 ca [2] 2d c0 [2] 3a cb [2] 21 85 [2] 1c }

  condition:
    any of them
}