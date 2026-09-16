rule TTP_XOR_MULT_DOSStub_cb87 {
  strings:
    $key_cb87 = { 9f ef [2] eb f7 [2] ac f5 [2] eb e4 [2] a5 e8 [2] a9 e2 [2] be e9 [2] a5 a7 [2] 98 }

  condition:
    any of them
}