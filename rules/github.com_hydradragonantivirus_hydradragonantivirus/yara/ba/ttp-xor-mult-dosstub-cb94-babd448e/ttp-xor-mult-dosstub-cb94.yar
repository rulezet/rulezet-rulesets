rule TTP_XOR_MULT_DOSStub_cb94 {
  strings:
    $key_cb94 = { 9f fc [2] eb e4 [2] ac e6 [2] eb f7 [2] a5 fb [2] a9 f1 [2] be fa [2] a5 b4 [2] 98 }

  condition:
    any of them
}