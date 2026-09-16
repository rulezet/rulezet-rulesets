rule TTP_XOR_MULT_DOSStub_2285 {
  strings:
    $key_2285 = { 76 ed [2] 02 f5 [2] 45 f7 [2] 02 e6 [2] 4c ea [2] 40 e0 [2] 57 eb [2] 4c a5 [2] 71 }

  condition:
    any of them
}