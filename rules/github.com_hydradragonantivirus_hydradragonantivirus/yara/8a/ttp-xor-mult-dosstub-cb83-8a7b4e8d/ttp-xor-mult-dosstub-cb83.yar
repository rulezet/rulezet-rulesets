rule TTP_XOR_MULT_DOSStub_cb83 {
  strings:
    $key_cb83 = { 9f eb [2] eb f3 [2] ac f1 [2] eb e0 [2] a5 ec [2] a9 e6 [2] be ed [2] a5 a3 [2] 98 }

  condition:
    any of them
}