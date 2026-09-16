rule TTP_XOR_MULT_DOSStub_939d {
  strings:
    $key_939d = { c7 f5 [2] b3 ed [2] f4 ef [2] b3 fe [2] fd f2 [2] f1 f8 [2] e6 f3 [2] fd bd [2] c0 }

  condition:
    any of them
}