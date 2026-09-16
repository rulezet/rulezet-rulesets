rule TTP_XOR_MULT_DOSStub_d985 {
  strings:
    $key_d985 = { 8d ed [2] f9 f5 [2] be f7 [2] f9 e6 [2] b7 ea [2] bb e0 [2] ac eb [2] b7 a5 [2] 8a }

  condition:
    any of them
}