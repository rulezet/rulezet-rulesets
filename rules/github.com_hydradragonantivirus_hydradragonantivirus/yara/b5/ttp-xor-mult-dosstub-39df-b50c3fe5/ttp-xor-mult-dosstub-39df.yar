rule TTP_XOR_MULT_DOSStub_39df {
  strings:
    $key_39df = { 6d b7 [2] 19 af [2] 5e ad [2] 19 bc [2] 57 b0 [2] 5b ba [2] 4c b1 [2] 57 ff [2] 6a }

  condition:
    any of them
}