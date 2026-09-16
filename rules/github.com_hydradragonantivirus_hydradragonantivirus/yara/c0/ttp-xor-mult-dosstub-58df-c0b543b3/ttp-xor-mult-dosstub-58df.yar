rule TTP_XOR_MULT_DOSStub_58df {
  strings:
    $key_58df = { 0c b7 [2] 78 af [2] 3f ad [2] 78 bc [2] 36 b0 [2] 3a ba [2] 2d b1 [2] 36 ff [2] 0b }

  condition:
    any of them
}