rule TTP_XOR_MULT_DOSStub_579a {
  strings:
    $key_579a = { 03 f2 [2] 77 ea [2] 30 e8 [2] 77 f9 [2] 39 f5 [2] 35 ff [2] 22 f4 [2] 39 ba [2] 04 }

  condition:
    any of them
}