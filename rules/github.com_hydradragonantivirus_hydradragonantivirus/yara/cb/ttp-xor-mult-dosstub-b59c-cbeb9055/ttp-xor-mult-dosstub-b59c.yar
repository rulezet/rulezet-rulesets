rule TTP_XOR_MULT_DOSStub_b59c {
  strings:
    $key_b59c = { e1 f4 [2] 95 ec [2] d2 ee [2] 95 ff [2] db f3 [2] d7 f9 [2] c0 f2 [2] db bc [2] e6 }

  condition:
    any of them
}