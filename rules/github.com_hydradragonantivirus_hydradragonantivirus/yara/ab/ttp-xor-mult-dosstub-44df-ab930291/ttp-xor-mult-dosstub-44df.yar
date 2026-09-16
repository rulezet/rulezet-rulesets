rule TTP_XOR_MULT_DOSStub_44df {
  strings:
    $key_44df = { 10 b7 [2] 64 af [2] 23 ad [2] 64 bc [2] 2a b0 [2] 26 ba [2] 31 b1 [2] 2a ff [2] 17 }

  condition:
    any of them
}