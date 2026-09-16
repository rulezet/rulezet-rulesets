rule TTP_XOR_MULT_DOSStub_cb80 {
  strings:
    $key_cb80 = { 9f e8 [2] eb f0 [2] ac f2 [2] eb e3 [2] a5 ef [2] a9 e5 [2] be ee [2] a5 a0 [2] 98 }

  condition:
    any of them
}