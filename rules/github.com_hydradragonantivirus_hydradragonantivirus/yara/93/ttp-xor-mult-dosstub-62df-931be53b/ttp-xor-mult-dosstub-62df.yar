rule TTP_XOR_MULT_DOSStub_62df {
  strings:
    $key_62df = { 36 b7 [2] 42 af [2] 05 ad [2] 42 bc [2] 0c b0 [2] 00 ba [2] 17 b1 [2] 0c ff [2] 31 }

  condition:
    any of them
}