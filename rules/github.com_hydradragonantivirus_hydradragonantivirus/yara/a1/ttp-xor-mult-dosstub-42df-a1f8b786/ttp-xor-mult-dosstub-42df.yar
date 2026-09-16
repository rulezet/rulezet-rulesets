rule TTP_XOR_MULT_DOSStub_42df {
  strings:
    $key_42df = { 16 b7 [2] 62 af [2] 25 ad [2] 62 bc [2] 2c b0 [2] 20 ba [2] 37 b1 [2] 2c ff [2] 11 }

  condition:
    any of them
}