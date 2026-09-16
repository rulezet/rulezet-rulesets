rule TTP_XOR_MULT_DOSStub_f78f {
  strings:
    $key_f78f = { a3 e7 [2] d7 ff [2] 90 fd [2] d7 ec [2] 99 e0 [2] 95 ea [2] 82 e1 [2] 99 af [2] a4 }

  condition:
    any of them
}