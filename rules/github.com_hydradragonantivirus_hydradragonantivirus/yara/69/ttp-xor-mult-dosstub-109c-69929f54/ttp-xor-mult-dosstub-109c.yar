rule TTP_XOR_MULT_DOSStub_109c {
  strings:
    $key_109c = { 44 f4 [2] 30 ec [2] 77 ee [2] 30 ff [2] 7e f3 [2] 72 f9 [2] 65 f2 [2] 7e bc [2] 43 }

  condition:
    any of them
}