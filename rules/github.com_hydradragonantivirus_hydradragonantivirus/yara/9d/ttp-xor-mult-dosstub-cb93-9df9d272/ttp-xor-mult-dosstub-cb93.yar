rule TTP_XOR_MULT_DOSStub_cb93 {
  strings:
    $key_cb93 = { 9f fb [2] eb e3 [2] ac e1 [2] eb f0 [2] a5 fc [2] a9 f6 [2] be fd [2] a5 b3 [2] 98 }

  condition:
    any of them
}