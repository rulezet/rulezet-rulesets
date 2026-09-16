rule TTP_XOR_MULT_DOSStub_f788 {
  strings:
    $key_f788 = { a3 e0 [2] d7 f8 [2] 90 fa [2] d7 eb [2] 99 e7 [2] 95 ed [2] 82 e6 [2] 99 a8 [2] a4 }

  condition:
    any of them
}