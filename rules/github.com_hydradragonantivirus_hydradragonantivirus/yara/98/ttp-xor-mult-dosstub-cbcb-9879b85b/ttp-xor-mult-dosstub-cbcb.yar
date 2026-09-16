rule TTP_XOR_MULT_DOSStub_cbcb {
  strings:
    $key_cbcb = { 9f a3 [2] eb bb [2] ac b9 [2] eb a8 [2] a5 a4 [2] a9 ae [2] be a5 [2] a5 eb [2] 98 }

  condition:
    any of them
}