rule TTP_XOR_MULT_DOSStub_5685 {
  strings:
    $key_5685 = { 02 ed [2] 76 f5 [2] 31 f7 [2] 76 e6 [2] 38 ea [2] 34 e0 [2] 23 eb [2] 38 a5 [2] 05 }

  condition:
    any of them
}