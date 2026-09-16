rule TTP_XOR_MULT_DOSStub_cbc1 {
  strings:
    $key_cbc1 = { 9f a9 [2] eb b1 [2] ac b3 [2] eb a2 [2] a5 ae [2] a9 a4 [2] be af [2] a5 e1 [2] 98 }

  condition:
    any of them
}