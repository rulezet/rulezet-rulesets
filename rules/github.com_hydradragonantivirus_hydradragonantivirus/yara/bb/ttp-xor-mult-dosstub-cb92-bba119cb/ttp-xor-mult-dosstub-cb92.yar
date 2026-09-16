rule TTP_XOR_MULT_DOSStub_cb92 {
  strings:
    $key_cb92 = { 9f fa [2] eb e2 [2] ac e0 [2] eb f1 [2] a5 fd [2] a9 f7 [2] be fc [2] a5 b2 [2] 98 }

  condition:
    any of them
}