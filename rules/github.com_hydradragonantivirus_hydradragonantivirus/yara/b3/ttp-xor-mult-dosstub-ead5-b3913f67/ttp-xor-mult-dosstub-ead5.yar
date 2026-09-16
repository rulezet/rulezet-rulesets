rule TTP_XOR_MULT_DOSStub_ead5 {
  strings:
    $key_ead5 = { be bd [2] ca a5 [2] 8d a7 [2] ca b6 [2] 84 ba [2] 88 b0 [2] 9f bb [2] 84 f5 [2] b9 }

  condition:
    any of them
}