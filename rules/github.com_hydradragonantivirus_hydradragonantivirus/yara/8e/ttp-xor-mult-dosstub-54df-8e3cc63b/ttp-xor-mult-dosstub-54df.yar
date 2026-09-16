rule TTP_XOR_MULT_DOSStub_54df {
  strings:
    $key_54df = { 00 b7 [2] 74 af [2] 33 ad [2] 74 bc [2] 3a b0 [2] 36 ba [2] 21 b1 [2] 3a ff [2] 07 }

  condition:
    any of them
}