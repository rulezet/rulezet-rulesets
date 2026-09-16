rule TTP_XOR_MULT_DOSStub_fab6 {
  strings:
    $key_fab6 = { ae de [2] da c6 [2] 9d c4 [2] da d5 [2] 94 d9 [2] 98 d3 [2] 8f d8 [2] 94 96 [2] a9 }

  condition:
    any of them
}