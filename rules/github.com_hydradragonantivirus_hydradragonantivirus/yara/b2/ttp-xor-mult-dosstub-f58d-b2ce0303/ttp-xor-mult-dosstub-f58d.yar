rule TTP_XOR_MULT_DOSStub_f58d {
  strings:
    $key_f58d = { a1 e5 [2] d5 fd [2] 92 ff [2] d5 ee [2] 9b e2 [2] 97 e8 [2] 80 e3 [2] 9b ad [2] a6 }

  condition:
    any of them
}