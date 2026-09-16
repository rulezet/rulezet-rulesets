rule TTP_XOR_MULT_DOSStub_f582 {
  strings:
    $key_f582 = { a1 ea [2] d5 f2 [2] 92 f0 [2] d5 e1 [2] 9b ed [2] 97 e7 [2] 80 ec [2] 9b a2 [2] a6 }

  condition:
    any of them
}