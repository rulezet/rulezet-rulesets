rule TTP_XOR_MULT_DOSStub_8ad4 {
  strings:
    $key_8ad4 = { de bc [2] aa a4 [2] ed a6 [2] aa b7 [2] e4 bb [2] e8 b1 [2] ff ba [2] e4 f4 [2] d9 }

  condition:
    any of them
}