rule TTP_XOR_MULT_DOSStub_f7cc {
  strings:
    $key_f7cc = { a3 a4 [2] d7 bc [2] 90 be [2] d7 af [2] 99 a3 [2] 95 a9 [2] 82 a2 [2] 99 ec [2] a4 }

  condition:
    any of them
}