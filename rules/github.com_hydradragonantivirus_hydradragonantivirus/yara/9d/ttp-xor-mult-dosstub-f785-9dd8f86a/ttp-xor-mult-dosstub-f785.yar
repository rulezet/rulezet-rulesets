rule TTP_XOR_MULT_DOSStub_f785 {
  strings:
    $key_f785 = { a3 ed [2] d7 f5 [2] 90 f7 [2] d7 e6 [2] 99 ea [2] 95 e0 [2] 82 eb [2] 99 a5 [2] a4 }

  condition:
    any of them
}