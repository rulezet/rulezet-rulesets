rule TTP_XOR_MULT_DOSStub_cbc4 {
  strings:
    $key_cbc4 = { 9f ac [2] eb b4 [2] ac b6 [2] eb a7 [2] a5 ab [2] a9 a1 [2] be aa [2] a5 e4 [2] 98 }

  condition:
    any of them
}