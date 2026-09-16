rule TTP_XOR_MULT_DOSStub_cbb1 {
  strings:
    $key_cbb1 = { 9f d9 [2] eb c1 [2] ac c3 [2] eb d2 [2] a5 de [2] a9 d4 [2] be df [2] a5 91 [2] 98 }

  condition:
    any of them
}