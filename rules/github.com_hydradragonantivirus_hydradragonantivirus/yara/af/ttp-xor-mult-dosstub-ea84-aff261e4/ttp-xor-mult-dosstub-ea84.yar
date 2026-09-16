rule TTP_XOR_MULT_DOSStub_ea84 {
  strings:
    $key_ea84 = { be ec [2] ca f4 [2] 8d f6 [2] ca e7 [2] 84 eb [2] 88 e1 [2] 9f ea [2] 84 a4 [2] b9 }

  condition:
    any of them
}