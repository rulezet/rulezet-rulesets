rule TTP_XOR_MULT_DOSStub_12df {
  strings:
    $key_12df = { 46 b7 [2] 32 af [2] 75 ad [2] 32 bc [2] 7c b0 [2] 70 ba [2] 67 b1 [2] 7c ff [2] 41 }

  condition:
    any of them
}