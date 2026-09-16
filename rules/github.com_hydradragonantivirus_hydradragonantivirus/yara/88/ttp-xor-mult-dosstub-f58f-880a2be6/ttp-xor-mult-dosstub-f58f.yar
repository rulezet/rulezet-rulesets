rule TTP_XOR_MULT_DOSStub_f58f {
  strings:
    $key_f58f = { a1 e7 [2] d5 ff [2] 92 fd [2] d5 ec [2] 9b e0 [2] 97 ea [2] 80 e1 [2] 9b af [2] a6 }

  condition:
    any of them
}