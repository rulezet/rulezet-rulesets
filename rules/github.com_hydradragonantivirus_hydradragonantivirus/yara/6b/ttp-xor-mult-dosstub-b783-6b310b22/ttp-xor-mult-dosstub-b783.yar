rule TTP_XOR_MULT_DOSStub_b783 {
  strings:
    $key_b783 = { e3 eb [2] 97 f3 [2] d0 f1 [2] 97 e0 [2] d9 ec [2] d5 e6 [2] c2 ed [2] d9 a3 [2] e4 }

  condition:
    any of them
}