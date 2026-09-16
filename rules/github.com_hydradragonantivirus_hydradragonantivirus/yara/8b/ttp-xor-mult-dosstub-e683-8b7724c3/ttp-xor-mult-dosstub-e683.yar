rule TTP_XOR_MULT_DOSStub_e683 {
  strings:
    $key_e683 = { b2 eb [2] c6 f3 [2] 81 f1 [2] c6 e0 [2] 88 ec [2] 84 e6 [2] 93 ed [2] 88 a3 [2] b5 }

  condition:
    any of them
}