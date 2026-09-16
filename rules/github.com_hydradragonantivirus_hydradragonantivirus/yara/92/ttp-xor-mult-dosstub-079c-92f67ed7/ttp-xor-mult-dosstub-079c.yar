rule TTP_XOR_MULT_DOSStub_079c {
  strings:
    $key_079c = { 53 f4 [2] 27 ec [2] 60 ee [2] 27 ff [2] 69 f3 [2] 65 f9 [2] 72 f2 [2] 69 bc [2] 54 }

  condition:
    any of them
}