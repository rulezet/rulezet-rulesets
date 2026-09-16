rule TTP_XOR_MULT_DOSStub_309c {
  strings:
    $key_309c = { 64 f4 [2] 10 ec [2] 57 ee [2] 10 ff [2] 5e f3 [2] 52 f9 [2] 45 f2 [2] 5e bc [2] 63 }

  condition:
    any of them
}