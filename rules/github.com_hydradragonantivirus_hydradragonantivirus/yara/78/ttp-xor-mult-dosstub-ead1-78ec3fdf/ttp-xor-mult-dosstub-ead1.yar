rule TTP_XOR_MULT_DOSStub_ead1 {
  strings:
    $key_ead1 = { be b9 [2] ca a1 [2] 8d a3 [2] ca b2 [2] 84 be [2] 88 b4 [2] 9f bf [2] 84 f1 [2] b9 }

  condition:
    any of them
}