rule TTP_XOR_MULT_DOSStub_029a {
  strings:
    $key_029a = { 56 f2 [2] 22 ea [2] 65 e8 [2] 22 f9 [2] 6c f5 [2] 60 ff [2] 77 f4 [2] 6c ba [2] 51 }

  condition:
    any of them
}