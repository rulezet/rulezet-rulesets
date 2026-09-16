rule TTP_XOR_MULT_DOSStub_28df {
  strings:
    $key_28df = { 7c b7 [2] 08 af [2] 4f ad [2] 08 bc [2] 46 b0 [2] 4a ba [2] 5d b1 [2] 46 ff [2] 7b }

  condition:
    any of them
}