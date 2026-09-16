rule TTP_XOR_MULT_DOSStub_7288 {
  strings:
    $key_7288 = { 26 e0 [2] 52 f8 [2] 15 fa [2] 52 eb [2] 1c e7 [2] 10 ed [2] 07 e6 [2] 1c a8 [2] 21 }

  condition:
    any of them
}