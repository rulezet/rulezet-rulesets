rule TTP_XOR_MULT_DOSStub_939a {
  strings:
    $key_939a = { c7 f2 [2] b3 ea [2] f4 e8 [2] b3 f9 [2] fd f5 [2] f1 ff [2] e6 f4 [2] fd ba [2] c0 }

  condition:
    any of them
}