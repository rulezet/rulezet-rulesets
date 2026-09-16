rule TTP_XOR_MULT_DOSStub_6fa5 {
  strings:
    $key_6fa5 = { 3b cd [2] 4f d5 [2] 08 d7 [2] 4f c6 [2] 01 ca [2] 0d c0 [2] 1a cb [2] 01 85 [2] 3c }

  condition:
    any of them
}