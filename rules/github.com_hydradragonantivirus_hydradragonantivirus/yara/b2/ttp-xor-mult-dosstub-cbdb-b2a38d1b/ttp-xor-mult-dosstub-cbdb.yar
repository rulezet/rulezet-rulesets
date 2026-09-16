rule TTP_XOR_MULT_DOSStub_cbdb {
  strings:
    $key_cbdb = { 9f b3 [2] eb ab [2] ac a9 [2] eb b8 [2] a5 b4 [2] a9 be [2] be b5 [2] a5 fb [2] 98 }

  condition:
    any of them
}