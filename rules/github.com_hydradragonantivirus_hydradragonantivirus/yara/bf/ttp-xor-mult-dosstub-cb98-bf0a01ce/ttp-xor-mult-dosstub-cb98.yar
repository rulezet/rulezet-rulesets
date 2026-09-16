rule TTP_XOR_MULT_DOSStub_cb98 {
  strings:
    $key_cb98 = { 9f f0 [2] eb e8 [2] ac ea [2] eb fb [2] a5 f7 [2] a9 fd [2] be f6 [2] a5 b8 [2] 98 }

  condition:
    any of them
}