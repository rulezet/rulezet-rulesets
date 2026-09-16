rule TTP_XOR_MULT_DOSStub_78df {
  strings:
    $key_78df = { 2c b7 [2] 58 af [2] 1f ad [2] 58 bc [2] 16 b0 [2] 1a ba [2] 0d b1 [2] 16 ff [2] 2b }

  condition:
    any of them
}