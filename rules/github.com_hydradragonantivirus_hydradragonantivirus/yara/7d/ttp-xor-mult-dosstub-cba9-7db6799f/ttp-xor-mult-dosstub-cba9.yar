rule TTP_XOR_MULT_DOSStub_cba9 {
  strings:
    $key_cba9 = { 9f c1 [2] eb d9 [2] ac db [2] eb ca [2] a5 c6 [2] a9 cc [2] be c7 [2] a5 89 [2] 98 }

  condition:
    any of them
}