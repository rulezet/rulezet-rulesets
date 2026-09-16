rule TTP_XOR_MULT_DOSStub_d085 {
  strings:
    $key_d085 = { 84 ed [2] f0 f5 [2] b7 f7 [2] f0 e6 [2] be ea [2] b2 e0 [2] a5 eb [2] be a5 [2] 83 }

  condition:
    any of them
}