rule TTP_XOR_MULT_DOSStub_eac7 {
  strings:
    $key_eac7 = { be af [2] ca b7 [2] 8d b5 [2] ca a4 [2] 84 a8 [2] 88 a2 [2] 9f a9 [2] 84 e7 [2] b9 }

  condition:
    any of them
}