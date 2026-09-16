rule TTP_XOR_MULT_DOSStub_08df {
  strings:
    $key_08df = { 5c b7 [2] 28 af [2] 6f ad [2] 28 bc [2] 66 b0 [2] 6a ba [2] 7d b1 [2] 66 ff [2] 5b }

  condition:
    any of them
}