rule TTP_XOR_MULT_DOSStub_7785 {
  strings:
    $key_7785 = { 23 ed [2] 57 f5 [2] 10 f7 [2] 57 e6 [2] 19 ea [2] 15 e0 [2] 02 eb [2] 19 a5 [2] 24 }

  condition:
    any of them
}