rule TTP_XOR_MULT_DOSStub_eadf {
  strings:
    $key_eadf = { be b7 [2] ca af [2] 8d ad [2] ca bc [2] 84 b0 [2] 88 ba [2] 9f b1 [2] 84 ff [2] b9 }

  condition:
    any of them
}