rule TTP_XOR_MULT_DOSStub_1385 {
  strings:
    $key_1385 = { 47 ed [2] 33 f5 [2] 74 f7 [2] 33 e6 [2] 7d ea [2] 71 e0 [2] 66 eb [2] 7d a5 [2] 40 }

  condition:
    any of them
}