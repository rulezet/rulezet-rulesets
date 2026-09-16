rule TTP_XOR_MULT_DOSStub_cb81 {
  strings:
    $key_cb81 = { 9f e9 [2] eb f1 [2] ac f3 [2] eb e2 [2] a5 ee [2] a9 e4 [2] be ef [2] a5 a1 [2] 98 }

  condition:
    any of them
}