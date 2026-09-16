rule TTP_XOR_MULT_DOSStub_34df {
  strings:
    $key_34df = { 60 b7 [2] 14 af [2] 53 ad [2] 14 bc [2] 5a b0 [2] 56 ba [2] 41 b1 [2] 5a ff [2] 67 }

  condition:
    any of them
}