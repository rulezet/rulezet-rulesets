rule TTP_XOR_MULT_DOSStub_779c {
  strings:
    $key_779c = { 23 f4 [2] 57 ec [2] 10 ee [2] 57 ff [2] 19 f3 [2] 15 f9 [2] 02 f2 [2] 19 bc [2] 24 }

  condition:
    any of them
}