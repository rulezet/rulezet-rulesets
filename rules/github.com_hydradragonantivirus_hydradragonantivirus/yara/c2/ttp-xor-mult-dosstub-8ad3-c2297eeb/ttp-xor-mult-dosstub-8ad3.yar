rule TTP_XOR_MULT_DOSStub_8ad3 {
  strings:
    $key_8ad3 = { de bb [2] aa a3 [2] ed a1 [2] aa b0 [2] e4 bc [2] e8 b6 [2] ff bd [2] e4 f3 [2] d9 }

  condition:
    any of them
}