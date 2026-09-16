rule TTP_XOR_MULT_DOSStub_fea5 {
  strings:
    $key_fea5 = { aa cd [2] de d5 [2] 99 d7 [2] de c6 [2] 90 ca [2] 9c c0 [2] 8b cb [2] 90 85 [2] ad }

  condition:
    any of them
}