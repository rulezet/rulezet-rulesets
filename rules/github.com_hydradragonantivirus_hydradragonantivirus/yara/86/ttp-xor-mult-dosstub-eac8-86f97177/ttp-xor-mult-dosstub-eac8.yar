rule TTP_XOR_MULT_DOSStub_eac8 {
  strings:
    $key_eac8 = { be a0 [2] ca b8 [2] 8d ba [2] ca ab [2] 84 a7 [2] 88 ad [2] 9f a6 [2] 84 e8 [2] b9 }

  condition:
    any of them
}