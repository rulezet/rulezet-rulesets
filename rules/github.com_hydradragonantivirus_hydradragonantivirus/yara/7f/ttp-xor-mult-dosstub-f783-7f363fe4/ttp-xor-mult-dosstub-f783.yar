rule TTP_XOR_MULT_DOSStub_f783 {
  strings:
    $key_f783 = { a3 eb [2] d7 f3 [2] 90 f1 [2] d7 e0 [2] 99 ec [2] 95 e6 [2] 82 ed [2] 99 a3 [2] a4 }

  condition:
    any of them
}