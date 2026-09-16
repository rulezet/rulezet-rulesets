rule TTP_XOR_MULT_DOSStub_cbc6 {
  strings:
    $key_cbc6 = { 9f ae [2] eb b6 [2] ac b4 [2] eb a5 [2] a5 a9 [2] a9 a3 [2] be a8 [2] a5 e6 [2] 98 }

  condition:
    any of them
}