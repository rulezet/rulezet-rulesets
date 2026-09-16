rule TTP_XOR_MULT_DOSStub_7285 {
  strings:
    $key_7285 = { 26 ed [2] 52 f5 [2] 15 f7 [2] 52 e6 [2] 1c ea [2] 10 e0 [2] 07 eb [2] 1c a5 [2] 21 }

  condition:
    any of them
}