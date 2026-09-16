rule TTP_XOR_MULT_DOSStub_7fa5 {
  strings:
    $key_7fa5 = { 2b cd [2] 5f d5 [2] 18 d7 [2] 5f c6 [2] 11 ca [2] 1d c0 [2] 0a cb [2] 11 85 [2] 2c }

  condition:
    any of them
}