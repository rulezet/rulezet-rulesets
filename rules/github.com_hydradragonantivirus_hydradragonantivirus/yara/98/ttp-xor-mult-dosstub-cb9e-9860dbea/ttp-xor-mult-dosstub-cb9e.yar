rule TTP_XOR_MULT_DOSStub_cb9e {
  strings:
    $key_cb9e = { 9f f6 [2] eb ee [2] ac ec [2] eb fd [2] a5 f1 [2] a9 fb [2] be f0 [2] a5 be [2] 98 }

  condition:
    any of them
}