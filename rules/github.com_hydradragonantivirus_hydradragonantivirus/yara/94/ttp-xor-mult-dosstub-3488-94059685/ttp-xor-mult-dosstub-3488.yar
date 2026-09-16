rule TTP_XOR_MULT_DOSStub_3488 {
  strings:
    $key_3488 = { 60 e0 [2] 14 f8 [2] 53 fa [2] 14 eb [2] 5a e7 [2] 56 ed [2] 41 e6 [2] 5a a8 [2] 67 }

  condition:
    any of them
}