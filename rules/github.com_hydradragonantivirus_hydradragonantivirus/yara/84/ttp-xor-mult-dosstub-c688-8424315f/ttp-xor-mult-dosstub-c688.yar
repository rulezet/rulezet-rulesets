rule TTP_XOR_MULT_DOSStub_c688 {
  strings:
    $key_c688 = { 92 e0 [2] e6 f8 [2] a1 fa [2] e6 eb [2] a8 e7 [2] a4 ed [2] b3 e6 [2] a8 a8 [2] 95 }

  condition:
    any of them
}