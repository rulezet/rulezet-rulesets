rule TTP_XOR_MULT_DOSStub_cb90 {
  strings:
    $key_cb90 = { 9f f8 [2] eb e0 [2] ac e2 [2] eb f3 [2] a5 ff [2] a9 f5 [2] be fe [2] a5 b0 [2] 98 }

  condition:
    any of them
}