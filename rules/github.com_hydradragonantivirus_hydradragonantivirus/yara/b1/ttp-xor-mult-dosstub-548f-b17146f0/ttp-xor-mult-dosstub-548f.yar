rule TTP_XOR_MULT_DOSStub_548f {
  strings:
    $key_548f = { 00 e7 [2] 74 ff [2] 33 fd [2] 74 ec [2] 3a e0 [2] 36 ea [2] 21 e1 [2] 3a af [2] 07 }

  condition:
    any of them
}