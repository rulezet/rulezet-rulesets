rule TTP_XOR_MULT_DOSStub_93b1 {
  strings:
    $key_93b1 = { c7 d9 [2] b3 c1 [2] f4 c3 [2] b3 d2 [2] fd de [2] f1 d4 [2] e6 df [2] fd 91 [2] c0 }

  condition:
    any of them
}