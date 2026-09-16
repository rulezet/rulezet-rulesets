rule TTP_XOR_MULT_DOSStub_cbc3 {
  strings:
    $key_cbc3 = { 9f ab [2] eb b3 [2] ac b1 [2] eb a0 [2] a5 ac [2] a9 a6 [2] be ad [2] a5 e3 [2] 98 }

  condition:
    any of them
}