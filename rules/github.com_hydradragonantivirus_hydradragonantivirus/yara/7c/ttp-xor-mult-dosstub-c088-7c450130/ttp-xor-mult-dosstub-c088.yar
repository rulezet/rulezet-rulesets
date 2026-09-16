rule TTP_XOR_MULT_DOSStub_c088 {
  strings:
    $key_c088 = { 94 e0 [2] e0 f8 [2] a7 fa [2] e0 eb [2] ae e7 [2] a2 ed [2] b5 e6 [2] ae a8 [2] 93 }

  condition:
    any of them
}