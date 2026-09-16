rule TTP_XOR_MULT_DOSStub_c488 {
  strings:
    $key_c488 = { 90 e0 [2] e4 f8 [2] a3 fa [2] e4 eb [2] aa e7 [2] a6 ed [2] b1 e6 [2] aa a8 [2] 97 }

  condition:
    any of them
}