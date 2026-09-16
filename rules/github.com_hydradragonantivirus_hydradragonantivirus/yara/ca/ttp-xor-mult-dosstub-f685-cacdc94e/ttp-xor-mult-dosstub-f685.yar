rule TTP_XOR_MULT_DOSStub_f685 {
  strings:
    $key_f685 = { a2 ed [2] d6 f5 [2] 91 f7 [2] d6 e6 [2] 98 ea [2] 94 e0 [2] 83 eb [2] 98 a5 [2] a5 }

  condition:
    any of them
}